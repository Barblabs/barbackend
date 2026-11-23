package postgres_test

import (
	"context"
	"encoding/json"
	"testing"

	"barbackend/internal/assessment"
	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

func TestAFindingsHistoryReadsItsPlacesFromTheFirstThatHoldsIt(t *testing.T) {
	t.Parallel()
	w := newFindingWorld(t)
	ctx := context.Background()
	first, second, payments, lab := chain(t, w)
	placements := inTxValue(t, w.db, func(tx *postgres.Tx) ([]postgres.PlacedFinding, error) {
		return tx.PrioritizationFindings(ctx, w.customer, second.ID)
	})
	kept := placements[0].Placement
	third := postgres.StoredPrioritization{ID: uuid.New(), Previous: &second.ID, Content: json.RawMessage(`{"list":{"groups":[]}}`), Findings: 1, Groups: 1}
	inTx(t, w.db, func(tx *postgres.Tx) (err error) {
		_, err = tx.CreatePrioritization(ctx, w.customer, third, readAt[1], []postgres.Placement{{Finding: payments, Group: 1, ScoreRank: 1, Kept: kept}})
		return err
	})
	versions := func(customer tenancy.CustomerID, finding uuid.UUID) []postgres.FindingVersion {
		return inTxValue(t, w.db, func(tx *postgres.Tx) ([]postgres.FindingVersion, error) {
			return tx.FindingVersions(ctx, customer, finding)
		})
	}

	got := versions(w.customer, lab)
	if len(got) != 2 || got[0].Prioritization != second.ID || got[1].Prioritization != third.ID || got[1].Place != nil {
		t.Fatalf("lab's versions = %+v, want the second holding it and the third not", got)
	}
	if p := got[0].Place; p == nil || p.Group != 2 || p.ScoreRank != 2 || !p.Placed.Equal(readAt[1]) || p.Placement != placements[1].Placement {
		t.Errorf("lab's place in the second = %+v", p)
	}
	if got := versions(w.customer, payments); len(got) != 3 || got[0].Prioritization != first.ID || got[0].Place.Placement != got[2].Place.Placement {
		t.Errorf("payments' versions = %+v, want all three with one placement", got)
	}
	if got := versions(newCustomer(t, w.db), lab); len(got) != 0 {
		t.Errorf("another Customer's versions = %+v, want none", got)
	}
}

func TestAFindingsHistoryReadsOnlyTheCustomersContentsDossiersAndFeedback(t *testing.T) {
	t.Parallel()
	w := newFindingWorld(t)
	ctx := context.Background()
	first, second, payments, lab := chain(t, w)
	placed := inTxValue(t, w.db, func(tx *postgres.Tx) ([]postgres.PlacedFinding, error) {
		return tx.PrioritizationFindings(ctx, w.customer, second.ID)
	})
	author := storeUser(t, w.db, "viewer@example.com", tenancy.Viewer, w.customer)
	inTx(t, w.db, func(tx *postgres.Tx) error {
		_, err := tx.AddFeedback(ctx, w.customer, second.ID, postgres.StoredFeedback{
			ID: uuid.New(), Finding: lab, Author: author.ID(), Verdict: assessment.VerdictShouldBeEarlier, Note: "es el de pagos",
		})
		return err
	})
	other := newCustomer(t, w.db)

	inTx(t, w.db, func(tx *postgres.Tx) error {
		ids := []uuid.UUID{first.ID, second.ID}
		if got, err := tx.PrioritizationContents(ctx, w.customer, ids); err != nil || len(got) != 2 || string(got[first.ID]) == "" {
			t.Errorf("contents = %v, %v, want both", got, err)
		}
		if got, err := tx.PrioritizationContents(ctx, other, ids); err != nil || len(got) != 0 {
			t.Errorf("another Customer's contents = %v, %v, want none", got, err)
		}
		both := []uuid.UUID{placed[0].Placement, placed[1].Placement}
		if got, err := tx.PlacementDossiers(ctx, w.customer, lab, both); err != nil || len(got) != 1 || string(got[placed[1].Placement]) != `{"finding": "lab"}` {
			t.Errorf("lab's dossiers = %s, %v, want only its own", got, err)
		}
		if got, err := tx.PlacementDossiers(ctx, other, lab, both); err != nil || len(got) != 0 {
			t.Errorf("another Customer's dossiers = %v, %v, want none", got, err)
		}
		if got, err := tx.FeedbackOnFinding(ctx, w.customer, lab); err != nil || len(got) != 1 || got[0].Note != "es el de pagos" {
			t.Errorf("feedback on lab = %+v, %v, want the one recorded", got, err)
		}
		if got, err := tx.FeedbackOnFinding(ctx, w.customer, payments); err != nil || len(got) != 0 {
			t.Errorf("feedback on payments = %+v, %v, want none", got, err)
		}
		return nil
	})
}
