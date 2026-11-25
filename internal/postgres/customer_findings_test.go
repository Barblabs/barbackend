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
	kev, epss := string(stixext.KEVDefinitionID), string(stixext.EPSSDefinitionID)
	inTx(t, w.db, func(tx *postgres.Tx) error {
		if _, err := tx.SetVulnerabilityExtension(context.Background(), "CVE-2021-23017", kev, json.RawMessage(`{"extension_type":"property-extension"}`)); err != nil {
			return err
		}
		_, err := tx.SetVulnerabilityExtension(context.Background(), "CVE-2021-23017", epss, json.RawMessage(`{"extension_type":"property-extension","probability":0.97}`))
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
		return tx.OpenFindingFactsOfCustomer(context.Background(), w.customer, kev, epss)
	})

	byID := map[finding.ID]postgres.OpenFindingFact{}
	for _, f := range facts {
		byID[f.ID] = f
	}
	p, okP := byID[payments]
	l, okL := byID[lab]
	if len(facts) != 2 || !okP || !okL {
		t.Fatalf("facts = %+v, want the Customer's two scored Findings", facts)
	}
	if p.AssetID != page.Assets[1].ID || p.Criticality != inventory.CriticalityHigh || p.Exposure != inventory.Internal || p.Area != nil {
		t.Errorf("payments asset facts = %+v, want High, declared Internal and in no Area", p)
	}
	if p.Product != (inventory.Product{Vendor: "f5", Name: "nginx"}) || p.Version != "1.18.0" || p.CVE != "CVE-2021-23017" {
		t.Errorf("payments product facts = %+v", p)
	}
	if band, _ := p.Score.Band(); !p.KEV || p.EPSS == nil || *p.EPSS != 0.97 || band != scoring.BandCritical {
		t.Errorf("payments threat facts = %+v, want in KEV, EPSS 0.97 and Critical", p)
	}
	if _, banded := l.Score.Band(); banded || l.Criticality != inventory.CriticalityLow || l.Exposure != inventory.ExposureUnknown {
		t.Errorf("lab facts = %+v, want unbanded, Low and Unknown", l)
	}
}
