package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"barbackend/internal/finding"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/scoring"
	"barbackend/internal/stixext"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

// paymentsScore is a Score of a Finding on the payments server.
var paymentsScore = scoring.Score{
	Model: 2, Value: 0.24624,
	Factors: scoring.Factors{
		Alpha: 0.81, Beta: 0.9, Gamma: 0, Vulnerability: 0.513,
		CriticalityMultiplier: 1, ExposureMultiplier: 0.6, LifecycleMultiplier: 0.8,
	},
	Gaps: []scoring.DataGap{scoring.EPSSPending, scoring.ExposureUndeclared},
}

func saveScore(t *testing.T, db *postgres.DB, id finding.ID, s scoring.Score) {
	t.Helper()
	inTx(t, db, func(tx *postgres.Tx) error {
		_, err := tx.SaveScoreIfChanged(context.Background(), id, s)
		return err
	})
}

func TestOpenFindingsOfCustomerReadWhatTheirDossiersNeed(t *testing.T) {
	t.Parallel()
	w := newFindingWorld(t)
	payments, _ := saveMatch(t, w.db, match(t, w.payments, "1.18.0"))
	saveScore(t, w.db, payments, paymentsScore)
	newer := paymentsScore
	newer.Value, newer.Gaps = 0.4, []scoring.DataGap{scoring.ExposureUndeclared}
	saveScore(t, w.db, payments, newer)
	saveMatch(t, w.db, match(t, w.lab, "1.18.0"))
	otherSource := newSource(t, w.db, newCustomer(t, w.db))
	syncRecords(t, w.db, otherSource.ID(), w.paymentsRecord(t))
	theirs, _ := saveMatch(t, w.db, match(t, inventory.SourceReference{Source: otherSource.ID(), RecordID: "1"}, "1.18.0"))
	saveScore(t, w.db, theirs, paymentsScore)

	got := inTxValue(t, w.db, func(tx *postgres.Tx) ([]postgres.CustomerFinding, error) {
		return tx.OpenFindingsOfCustomer(context.Background(), w.customer)
	})

	if len(got) != 1 {
		t.Fatalf("open findings = %+v, want only the Customer's scored one", got)
	}
	f := got[0]
	if f.ID != payments || f.CVE != "CVE-2021-23017" || f.ComponentName != nginx.Name || f.ComponentVersion != "1.18.0" || len(f.Vulnerability) == 0 {
		t.Errorf("finding = %+v", f)
	}
	if f.Asset.Imported().Name() != "payments" || len(f.Asset.Imported().Software()) != 3 {
		t.Errorf("asset = %+v, want the payments server with its software", f.Asset.Imported())
	}
	if f.Score.Value != 0.4 || !slices.Equal(f.Score.Gaps, newer.Gaps) || f.Score.Factors != newer.Factors {
		t.Errorf("score = %+v, want the latest", f.Score)
	}

	inTx(t, w.db, func(tx *postgres.Tx) error {
		_, err := tx.CloseFinding(context.Background(), payments, finding.NoLongerAffected)
		return err
	})
	if open := inTxValue(t, w.db, func(tx *postgres.Tx) ([]postgres.CustomerFinding, error) {
		return tx.OpenFindingsOfCustomer(context.Background(), w.customer)
	}); len(open) != 0 {
		t.Errorf("open findings after closing = %+v", open)
	}
	closed := inTxValue(t, w.db, func(tx *postgres.Tx) (postgres.CustomerFinding, error) {
		return tx.FindingOfCustomer(context.Background(), w.customer, uuid.UUID(payments))
	})
	if closed.ID != payments || closed.Score.Value != 0.4 {
		t.Errorf("closed finding = %+v, want it read too", closed)
	}
	err := w.db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.FindingOfCustomer(context.Background(), w.customer, uuid.UUID(theirs))
		return err
	})
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("another Customer's finding: err = %v, want ErrNotFound", err)
	}
}

func TestFindingWeeksOfCustomerCountOnlyItsOwnFindings(t *testing.T) {
	t.Parallel()
	w := newFindingWorld(t)
	saveMatch(t, w.db, match(t, w.payments, "1.18.0"))
	other := newSource(t, w.db, newCustomer(t, w.db))
	syncRecords(t, w.db, other.ID(), w.paymentsRecord(t))
	saveMatch(t, w.db, match(t, inventory.SourceReference{Source: other.ID(), RecordID: "1"}, "1.18.0"))

	since := time.Now().Add(-time.Hour).Truncate(time.Microsecond)
	weeks := inTxValue(t, w.db, func(tx *postgres.Tx) ([]postgres.FindingWeek, error) {
		return tx.FindingWeeksOfCustomer(context.Background(), w.customer, since.Add(-168*time.Hour), 2)
	})

	if len(weeks) != 2 || !weeks[1].Start.Equal(since) {
		t.Fatalf("weeks = %+v, want two, the last starting at %v", weeks, since)
	}
	if weeks[0].Opened != 0 || weeks[0].OpenAtEnd != 0 || weeks[1].Opened != 1 || weeks[1].Closed != 0 || weeks[1].OpenAtEnd != 1 {
		t.Errorf("weeks = %+v, want the Customer's one Finding opened and open in the last week only", weeks)
	}
}

func TestFindingWeeksOfCustomerReadEachOpenFindingsScoreAtTheWeeksEnd(t *testing.T) {
	t.Parallel()
	w := newFindingWorld(t)
	payments, _ := saveMatch(t, w.db, match(t, w.payments, "1.18.0"))
	high, critical := modelThree(0.5), modelThree(0.8)
	saveScore(t, w.db, payments, high)
	firstWeekEnd := time.Now().Truncate(time.Microsecond)
	saveScore(t, w.db, payments, critical)

	weeks := inTxValue(t, w.db, func(tx *postgres.Tx) ([]postgres.FindingWeek, error) {
		return tx.FindingWeeksOfCustomer(context.Background(), w.customer, firstWeekEnd.Add(-168*time.Hour), 2)
	})

	if len(weeks) != 2 {
		t.Fatalf("weeks = %+v, want two", weeks)
	}
	for i, want := range []scoring.Score{high, critical} {
		if got := weeks[i].ScoresAtEnd; len(got) != 1 || got[0].Model != want.Model || got[0].Value != want.Value {
			t.Errorf("week %d scores at end = %+v, want only payments' %v", i, got, want.Value)
		}
	}
}

// modelThree is paymentsScore as Scoring Model 3 scores it, with that value.
func modelThree(value float64) scoring.Score {
	s := paymentsScore
	s.Model, s.Value = 3, value
	return s
}

func TestOpenFindingFactsOfCustomerReadWhatTheDashboardCountsBy(t *testing.T) {
	t.Parallel()
	w := newFindingWorld(t)
	payments, _ := saveMatch(t, w.db, match(t, w.payments, "1.18.0"))
	saveScore(t, w.db, payments, modelThree(0.75))
	lab, _ := saveMatch(t, w.db, match(t, w.lab, "1.18.0"))
	saveScore(t, w.db, lab, paymentsScore)
	kev := string(stixext.KEVDefinitionID)
	inTx(t, w.db, func(tx *postgres.Tx) error {
		_, err := tx.SetVulnerabilityExtension(context.Background(), "CVE-2021-23017", kev, json.RawMessage(`{"extension_type":"property-extension"}`))
		return err
	})
	var page postgres.AssetPage
	inTx(t, w.db, func(tx *postgres.Tx) (err error) {
		page, err = tx.ListAssets(context.Background(), postgres.AssetListQuery{Customer: w.customer, Limit: 10})
		return err
	})
	admin := storeUser(t, w.db, "admin@example.com", tenancy.CustomerAdmin, w.customer)
	declareInternal(t, w.db, w.customer, page.Assets[1].ID, admin.ID())
	otherSource := newSource(t, w.db, newCustomer(t, w.db))
	syncRecords(t, w.db, otherSource.ID(), w.paymentsRecord(t))
	theirs, _ := saveMatch(t, w.db, match(t, inventory.SourceReference{Source: otherSource.ID(), RecordID: "1"}, "1.18.0"))
	saveScore(t, w.db, theirs, modelThree(0.75))

	facts := inTxValue(t, w.db, func(tx *postgres.Tx) ([]postgres.OpenFindingFact, error) {
		return tx.OpenFindingFactsOfCustomer(context.Background(), w.customer, kev)
	})

	p := slices.IndexFunc(facts, func(f postgres.OpenFindingFact) bool { return f.Score.Model == 3 })
	l := slices.IndexFunc(facts, func(f postgres.OpenFindingFact) bool { return f.Score.Model == paymentsScore.Model })
	if len(facts) != 2 || p < 0 || l < 0 {
		t.Fatalf("facts = %+v, want the Customer's two scored Findings", facts)
	}
	if f := facts[p]; f.Exposure != inventory.Internal || f.CVE != "CVE-2021-23017" || !f.KEV || f.Score.Value != 0.75 {
		t.Errorf("payments facts = %+v, want declared Internal, in KEV and its latest Score", f)
	}
	if _, banded := facts[l].Score.Band(); banded || facts[l].Exposure != inventory.ExposureUnknown {
		t.Errorf("lab facts = %+v, want unbanded and Unknown", facts[l])
	}
}
