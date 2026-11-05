package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"barbackend/internal/assessment"
	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

func TestPrioritizationsStayWithTheirCustomer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, _ := newDBWithConn(t)
	customer, other := newCustomer(t, db), newCustomer(t, db)
	author, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "viewer@example.com", tenancy.Viewer, customer)
	if err != nil {
		t.Fatal(err)
	}
	inTx(t, db, func(tx *postgres.Tx) error {
		_, err := tx.CreateUser(ctx, author, uuid.NewString())
		return err
	})
	older, newer := uuid.New(), uuid.New()
	content := json.RawMessage(`{"findings":[{"finding":"f-1"},{"finding":"f-2"}]}`)
	for _, id := range []uuid.UUID{older, newer} {
		inTx(t, db, func(tx *postgres.Tx) error {
			_, err := tx.CreatePrioritization(ctx, customer, postgres.StoredPrioritization{ID: id, Content: content, Findings: 2, Groups: 1})
			return err
		})
	}

	list := inTxValue(t, db, func(tx *postgres.Tx) ([]postgres.PrioritizationSummary, error) {
		return tx.ListPrioritizations(ctx, customer, 10)
	})
	if len(list) != 2 || list[0].ID != newer || list[0].Findings != 2 || list[0].Groups != 1 {
		t.Errorf("list = %+v, want the newer first", list)
	}
	if got := inTxValue(t, db, func(tx *postgres.Tx) ([]postgres.PrioritizationSummary, error) {
		return tx.ListPrioritizations(ctx, other, 10)
	}); len(got) != 0 {
		t.Errorf("another Customer's list = %+v", got)
	}

	holds := func(customer tenancy.CustomerID, finding string) (bool, error) {
		return postgres.InTxValue(ctx, db, func(tx *postgres.Tx) (bool, error) { return tx.PrioritizationHolds(ctx, customer, newer, finding) })
	}
	if ok, err := holds(customer, "f-2"); err != nil || !ok {
		t.Errorf("holds f-2 = %v, %v", ok, err)
	}
	if ok, err := holds(customer, "f-9"); err != nil || ok {
		t.Errorf("holds f-9 = %v, %v", ok, err)
	}
	if _, err := holds(other, "f-2"); !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("another Customer: err = %v, want ErrNotFound", err)
	}

	for _, plan := range []string{`{"n":1}`, `{"n":2}`} {
		inTx(t, db, func(tx *postgres.Tx) error {
			_, err := tx.CreatePlan(ctx, customer, newer, postgres.StoredPlan{ID: uuid.New(), Finding: "f-1", Content: json.RawMessage(plan)})
			return err
		})
	}
	err = db.InTx(ctx, func(tx *postgres.Tx) error {
		_, err := tx.CreatePlan(ctx, other, newer, postgres.StoredPlan{ID: uuid.New(), Finding: "f-1", Content: json.RawMessage(`{}`)})
		return err
	})
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("a plan on another Customer's prioritization: err = %v, want ErrNotFound", err)
	}
	plans := inTxValue(t, db, func(tx *postgres.Tx) ([]postgres.StoredPlan, error) { return tx.LatestPlans(ctx, customer, newer) })
	if len(plans) != 1 || plans[0].Finding != "f-1" || string(plans[0].Content) != `{"n": 2}` {
		t.Errorf("plans = %+v, want only the newest", plans)
	}

	feedback := postgres.StoredFeedback{ID: uuid.New(), Finding: "f-2", Author: author.ID(), Verdict: assessment.VerdictShouldBeEarlier, Note: "es el de pagos"}
	stored := inTxValue(t, db, func(tx *postgres.Tx) (postgres.StoredFeedback, error) {
		return tx.AddFeedback(ctx, customer, newer, feedback)
	})
	if stored.Created.IsZero() {
		t.Error("feedback has no creation time")
	}
	err = db.InTx(ctx, func(tx *postgres.Tx) error {
		_, err := tx.AddFeedback(ctx, other, newer, postgres.StoredFeedback{ID: uuid.New(), Finding: "f-2", Author: author.ID(), Verdict: assessment.VerdictApplies})
		return err
	})
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("feedback on another Customer's prioritization: err = %v, want ErrNotFound", err)
	}
	got := inTxValue(t, db, func(tx *postgres.Tx) ([]postgres.StoredFeedback, error) { return tx.Feedback(ctx, customer, newer) })
	if len(got) != 1 || got[0].Finding != "f-2" || got[0].Verdict != assessment.VerdictShouldBeEarlier || got[0].Note != feedback.Note {
		t.Errorf("feedback = %+v", got)
	}
}

func inTxValue[T any](t *testing.T, db *postgres.DB, fn func(*postgres.Tx) (T, error)) T {
	t.Helper()
	v, err := postgres.InTxValue(context.Background(), db, fn)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
