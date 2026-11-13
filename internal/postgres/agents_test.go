package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"barbackend/internal/assessment"
	"barbackend/internal/finding"
	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

func TestConversationHistoryAndClaim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, _ := newDBWithConn(t)
	customer := newCustomer(t, db)
	user, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "viewer@example.com", tenancy.Viewer, customer)
	if err != nil {
		t.Fatal(err)
	}
	inTx(t, db, func(tx *postgres.Tx) error {
		_, err := tx.CreateUser(ctx, user, uuid.NewString())
		return err
	})
	owner := postgres.ConversationOwner{Customer: customer, User: user.ID()}
	id := uuid.New()
	history := json.RawMessage(`[{"role":"user",  "content":[{"z":1.0,"a":"  texto  "}]}]`)
	inTx(t, db, func(tx *postgres.Tx) error { return tx.CreateConversation(ctx, owner, id, history) })
	claim := func(lifetime time.Duration) (postgres.StoredConversation, error) {
		return postgres.InTxValue(ctx, db, func(tx *postgres.Tx) (postgres.StoredConversation, error) {
			return tx.ClaimConversation(ctx, owner, id, lifetime)
		})
	}

	stored, err := claim(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored.History) != string(history) || stored.Turns != 1 {
		t.Errorf("stored = %s turn %d, want %s turn 1", stored.History, stored.Turns, history)
	}

	if _, err := claim(time.Hour); !errors.Is(err, postgres.ErrConversationClaimed) {
		t.Errorf("a second claim: err = %v, want ErrConversationClaimed", err)
	}
	if _, err := claim(0); err != nil {
		t.Errorf("claim over a stale one: err = %v", err)
	}

	stranger := postgres.ConversationOwner{Customer: customer, User: tenancy.UserID(uuid.New())}
	err = db.InTx(ctx, func(tx *postgres.Tx) error {
		_, err := tx.ClaimConversation(ctx, stranger, id, time.Hour)
		return err
	})
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("another User's claim: err = %v, want ErrNotFound", err)
	}
	inTx(t, db, func(tx *postgres.Tx) error { return tx.ReleaseConversation(ctx, stranger, id, 1) })
	if _, err := claim(time.Hour); !errors.Is(err, postgres.ErrConversationClaimed) {
		t.Errorf("after another User's release: err = %v, want the claim to hold", err)
	}
	err = db.InTx(ctx, func(tx *postgres.Tx) error {
		return tx.AdvanceConversation(ctx, stranger, id, 1, json.RawMessage(`[9]`))
	})
	if !errors.Is(err, postgres.ErrConversationClaimed) {
		t.Errorf("another User's advance: err = %v, want ErrConversationClaimed", err)
	}

	inTx(t, db, func(tx *postgres.Tx) error { return tx.ReleaseConversation(ctx, owner, id, 1) })
	if _, err := claim(time.Hour); err != nil {
		t.Errorf("claim after a release: err = %v", err)
	}

	inTx(t, db, func(tx *postgres.Tx) error { return tx.AdvanceConversation(ctx, owner, id, 1, json.RawMessage(`[1]`)) })
	err = db.InTx(ctx, func(tx *postgres.Tx) error { return tx.AdvanceConversation(ctx, owner, id, 1, json.RawMessage(`[2]`)) })
	if !errors.Is(err, postgres.ErrConversationClaimed) {
		t.Errorf("advancing a stale copy: err = %v, want ErrConversationClaimed", err)
	}
	stored, err = claim(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored.History) != `[1]` || stored.Turns != 2 {
		t.Errorf("after advancing = %s turn %d", stored.History, stored.Turns)
	}
}

// readAt is when the rounds of chain read what they placed.
var readAt = []time.Time{time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC), time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)}

// chain stores two Prioritizations of the Customer of w, the second built
// from the first, over a Finding on the payments server and one on the lab
// server. The second keeps the first's placement of the payments one and
// places the lab one.
func chain(t *testing.T, w findingWorld) (first, second postgres.StoredPrioritization, payments, lab uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	p, _ := saveMatch(t, w.db, match(t, w.payments, "1.18.0"))
	l, _ := saveMatch(t, w.db, match(t, w.lab, "1.18.0"))
	payments, lab = uuid.UUID(p), uuid.UUID(l)
	content := json.RawMessage(`{"list":{"groups":[]}}`)
	first = postgres.StoredPrioritization{ID: uuid.New(), Content: content, Findings: 1, Groups: 1}
	inTx(t, w.db, func(tx *postgres.Tx) (err error) {
		first.Created, err = tx.CreatePrioritization(ctx, w.customer, first, readAt[0], []postgres.Placement{
			{Finding: payments, Group: 1, ScoreRank: 1, Dossier: json.RawMessage(`{"finding":"payments"}`)},
		})
		return err
	})
	kept := inTxValue(t, w.db, func(tx *postgres.Tx) ([]postgres.PlacedFinding, error) {
		return tx.PrioritizationFindings(ctx, w.customer, first.ID)
	})[0].Placement
	second = postgres.StoredPrioritization{ID: uuid.New(), Previous: &first.ID, Content: content, Findings: 2, Groups: 2}
	inTx(t, w.db, func(tx *postgres.Tx) (err error) {
		second.Created, err = tx.CreatePrioritization(ctx, w.customer, second, readAt[1], []postgres.Placement{
			{Finding: payments, Group: 1, ScoreRank: 1, Kept: kept},
			{Finding: lab, Group: 2, ScoreRank: 2, Dossier: json.RawMessage(`{"finding":"lab"}`)},
		})
		return err
	})
	return first, second, payments, lab
}

func TestPrioritizationsFormOneChainPerCustomer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newFindingWorld(t)
	first, second, payments, lab := chain(t, w)
	other := newCustomer(t, w.db)
	create := func(customer tenancy.CustomerID, previous *uuid.UUID) error {
		return w.db.InTx(ctx, func(tx *postgres.Tx) error {
			_, err := tx.CreatePrioritization(ctx, customer, postgres.StoredPrioritization{ID: uuid.New(), Previous: previous, Content: json.RawMessage(`{}`)}, time.Now(), nil)
			return err
		})
	}

	newest := inTxValue(t, w.db, func(tx *postgres.Tx) (postgres.StoredPrioritization, error) {
		return tx.NewestPrioritization(ctx, w.customer)
	})
	if newest.ID != second.ID || newest.Previous == nil || *newest.Previous != first.ID {
		t.Errorf("newest = %+v, want the second, built from the first", newest)
	}
	if err := create(w.customer, nil); !errors.Is(err, postgres.ErrNotNewest) {
		t.Errorf("a second first prioritization: err = %v, want ErrNotNewest", err)
	}
	if err := create(w.customer, &first.ID); !errors.Is(err, postgres.ErrNotNewest) {
		t.Errorf("another built from the first: err = %v, want ErrNotNewest", err)
	}
	if err := create(other, nil); err != nil {
		t.Errorf("another Customer's first: %v", err)
	}
	err := w.db.InTx(ctx, func(tx *postgres.Tx) error {
		_, err := tx.Prioritization(ctx, other, second.ID)
		return err
	})
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("another Customer reading it: err = %v, want ErrNotFound", err)
	}
	list := inTxValue(t, w.db, func(tx *postgres.Tx) ([]postgres.PrioritizationSummary, error) {
		return tx.ListPrioritizations(ctx, w.customer, 10)
	})
	if len(list) != 2 || list[0].ID != second.ID || list[0].Findings != 2 || list[0].Groups != 2 {
		t.Errorf("list = %+v, want the second first", list)
	}

	inTx(t, w.db, func(tx *postgres.Tx) error {
		_, err := tx.CloseFinding(ctx, finding.ID(lab), finding.NoLongerAffected)
		return err
	})
	placed := inTxValue(t, w.db, func(tx *postgres.Tx) ([]postgres.PlacedFinding, error) {
		return tx.PrioritizationFindings(ctx, w.customer, second.ID)
	})
	if len(placed) != 2 || placed[0].Finding != payments || !placed[0].Placed.Equal(readAt[0]) || string(placed[0].Dossier) != `{"finding": "payments"}` || placed[0].Closed != nil {
		t.Errorf("kept finding = %+v, want it with the placement of the first, open", placed)
	}
	if placed[1].Finding != lab || !placed[1].Placed.Equal(readAt[1]) || string(placed[1].Dossier) != `{"finding": "lab"}` || placed[1].Closed == nil {
		t.Errorf("placed finding = %+v, want it placed by the second, closed", placed[1])
	}
	if err := w.db.InTx(ctx, func(tx *postgres.Tx) error {
		_, err := tx.CreatePrioritization(ctx, w.customer, postgres.StoredPrioritization{ID: uuid.New(), Previous: &second.ID, Content: json.RawMessage(`{}`)}, time.Now(), []postgres.Placement{
			{Finding: lab, Group: 1, ScoreRank: 1, Kept: placed[0].Placement},
		})
		return err
	}); err == nil {
		t.Error("a Finding kept another Finding's placement")
	}
}

func TestPlansAndFeedbackHoldForAFindingAcrossTheChain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newFindingWorld(t)
	first, second, payments, lab := chain(t, w)
	other := newCustomer(t, w.db)
	author, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "viewer@example.com", tenancy.Viewer, w.customer)
	if err != nil {
		t.Fatal(err)
	}
	inTx(t, w.db, func(tx *postgres.Tx) error {
		_, err := tx.CreateUser(ctx, author, uuid.NewString())
		return err
	})

	holds := func(customer tenancy.CustomerID, finding uuid.UUID) (bool, error) {
		return postgres.InTxValue(ctx, w.db, func(tx *postgres.Tx) (bool, error) { return tx.PrioritizationHolds(ctx, customer, first.ID, finding) })
	}
	if ok, err := holds(w.customer, payments); err != nil || !ok {
		t.Errorf("holds the payments finding = %v, %v", ok, err)
	}
	if ok, err := holds(w.customer, lab); err != nil || ok {
		t.Errorf("holds the lab finding, which only the second placed = %v, %v", ok, err)
	}
	if _, err := holds(other, payments); !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("another Customer: err = %v, want ErrNotFound", err)
	}

	for _, plan := range []string{`{"n":1}`, `{"n":2}`} {
		inTx(t, w.db, func(tx *postgres.Tx) error {
			_, err := tx.CreatePlan(ctx, w.customer, first.ID, postgres.StoredPlan{ID: uuid.New(), Finding: payments, Content: json.RawMessage(plan)})
			return err
		})
	}
	err = w.db.InTx(ctx, func(tx *postgres.Tx) error {
		_, err := tx.CreatePlan(ctx, other, first.ID, postgres.StoredPlan{ID: uuid.New(), Finding: payments, Content: json.RawMessage(`{}`)})
		return err
	})
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("a plan on another Customer's prioritization: err = %v, want ErrNotFound", err)
	}
	if err := w.db.InTx(ctx, func(tx *postgres.Tx) error {
		_, err := tx.CreatePlan(ctx, w.customer, first.ID, postgres.StoredPlan{ID: uuid.New(), Finding: lab, Content: json.RawMessage(`{}`)})
		return err
	}); err == nil {
		t.Error("a plan for a Finding the Prioritization does not hold was stored")
	}
	plans := inTxValue(t, w.db, func(tx *postgres.Tx) ([]postgres.StoredPlan, error) {
		return tx.LatestPlans(ctx, w.customer, second.ID)
	})
	if len(plans) != 1 || plans[0].Finding != payments || string(plans[0].Content) != `{"n": 2}` {
		t.Errorf("plans read from the second = %+v, want the newest asked from the first", plans)
	}

	earlier := postgres.StoredFeedback{ID: uuid.New(), Finding: lab, Author: author.ID(), Verdict: assessment.VerdictShouldBeEarlier, Note: "es el de pagos"}
	applies := postgres.StoredFeedback{ID: uuid.New(), Finding: payments, Author: author.ID(), Verdict: assessment.VerdictApplies}
	for _, f := range []postgres.StoredFeedback{earlier, applies} {
		stored := inTxValue(t, w.db, func(tx *postgres.Tx) (postgres.StoredFeedback, error) {
			return tx.AddFeedback(ctx, w.customer, second.ID, f)
		})
		if stored.Created.IsZero() {
			t.Error("feedback has no creation time")
		}
	}
	err = w.db.InTx(ctx, func(tx *postgres.Tx) error {
		_, err := tx.AddFeedback(ctx, other, second.ID, applies)
		return err
	})
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("feedback on another Customer's prioritization: err = %v, want ErrNotFound", err)
	}
	got := inTxValue(t, w.db, func(tx *postgres.Tx) ([]postgres.StoredFeedback, error) {
		return tx.Feedback(ctx, w.customer, first.ID)
	})
	if len(got) != 1 || got[0].Finding != payments || got[0].Verdict != assessment.VerdictApplies {
		t.Errorf("feedback read from the first = %+v, want what was said of its Finding", got)
	}
}

func TestDisconnectingASourceClosesTheFindingsOfItsAssets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newFindingWorld(t)
	saveMatch(t, w.db, match(t, w.payments, "1.18.0"))

	inTx(t, w.db, func(tx *postgres.Tx) error { return tx.DisconnectCMDBSource(ctx, w.customer) })

	if open := openFindingsOf(t, w.db, "CVE-2021-23017"); len(open) != 0 {
		t.Errorf("open findings = %+v, want none of a Disconnected source", open)
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
