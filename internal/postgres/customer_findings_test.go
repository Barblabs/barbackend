package postgres_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"barbackend/internal/finding"
	"barbackend/internal/inventory"
	"barbackend/internal/matching"
	"barbackend/internal/postgres"
	"barbackend/internal/scoring"
	"barbackend/internal/stixext"
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

	weeks := inTxValue(t, w.db, func(tx *postgres.Tx) ([]postgres.FindingWeek, error) {
		return tx.FindingWeeksOfCustomer(context.Background(), w.customer, time.Now().AddDate(0, 0, -14))
	})

	if len(weeks) != 1 || weeks[0].Opened != 1 || weeks[0].Closed != 0 || weeks[0].Start.Weekday() != time.Monday {
		t.Errorf("weeks = %+v, want one week starting on a Monday with the Customer's one Finding opened", weeks)
	}
}

func TestFindingBandsByAssetOfCustomerCountTheLatestScoreOfOpenFindings(t *testing.T) {
	t.Parallel()
	w := newFindingWorld(t)
	banded := func(value float64) scoring.Score {
		s := paymentsScore
		s.Model, s.Value = 3, value
		return s
	}
	paymentsNginx, _ := saveMatch(t, w.db, match(t, w.payments, "1.18.0"))
	saveScore(t, w.db, paymentsNginx, banded(0.75))
	storeVulnerability(t, w.db, "CVE-2024-0001", time.Now(), vulnerabilityObject("CVE-2024-0001", "Analyzed", `[]`))
	vaultMatch, err := finding.NewMatch(w.payments, vault, "CVE-2024-0001", matching.Result{Matched: true, Evidence: stixext.Affected{Vendor: "hashicorp", Product: "vault", Version: "*"}})
	if err != nil {
		t.Fatal(err)
	}
	paymentsVault, _ := saveMatch(t, w.db, vaultMatch)
	saveScore(t, w.db, paymentsVault, banded(0.39995)) // shown as 0.4: High
	lab, _ := saveMatch(t, w.db, match(t, w.lab, "1.18.0"))
	saveScore(t, w.db, lab, banded(0.75))
	saveScore(t, w.db, lab, paymentsScore) // its latest Score is from Model 2
	otherSource := newSource(t, w.db, newCustomer(t, w.db))
	syncRecords(t, w.db, otherSource.ID(), w.paymentsRecord(t))
	theirs, _ := saveMatch(t, w.db, match(t, inventory.SourceReference{Source: otherSource.ID(), RecordID: "1"}, "1.18.0"))
	saveScore(t, w.db, theirs, banded(0.1))

	got := inTxValue(t, w.db, func(tx *postgres.Tx) ([]postgres.AssetFindingBands, error) {
		return tx.FindingBandsByAssetOfCustomer(context.Background(), w.customer)
	})

	if len(got) != 2 || got[0].AssetName != "lab" || got[1].AssetName != "payments" {
		t.Fatalf("assets = %+v, want lab then payments, and none of the other Customer", got)
	}
	if lab := got[0]; lab.Unbanded != 1 || lab.Critical+lab.High+lab.Medium+lab.Low != 0 {
		t.Errorf("lab = %+v, want its one Finding unbanded by its latest Score", lab)
	}
	if p := got[1]; p.Critical != 1 || p.High != 1 || p.Medium+p.Low+p.Unbanded != 0 || p.AssetID == 0 {
		t.Errorf("payments = %+v, want one Critical and one High", p)
	}
}
