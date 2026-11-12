package postgres_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"barbackend/internal/finding"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/scoring"
	"github.com/google/uuid"
)

// paymentsScore is a Score of a Finding on the payments server.
var paymentsScore = scoring.Score{
	Model: 1, Value: 0.308,
	Factors: scoring.Factors{Alpha: 0.81, Beta: 0.9, Gamma: 0, Vulnerability: 0.513, CriticalityMultiplier: 1, ExposureMultiplier: 0.6},
	Gaps:    []scoring.DataGap{scoring.EPSSPending, scoring.ExposureUndeclared},
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
