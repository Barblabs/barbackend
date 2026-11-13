package agents_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"barbackend/internal/agents"
	"barbackend/internal/claude/claudetest"
	"barbackend/internal/finding"
	"barbackend/internal/postgres"
	"github.com/google/uuid"
)

func TestListShowsTheCustomersNewestFirst(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	older := e.prioritize(t)
	e.rescore(t, e.os(), score(0.1))
	e.llm.Queue(claudetest.JSON(t, placement(standing(1), newGroup("Al final", e.os(), "Ubuntu Server 22.04 bajó.", osEvidence(e)))))
	if _, err := e.svc.Prioritize(context.Background(), e.customer); err != nil {
		t.Fatal(err)
	}
	newer := e.latest(t)
	stranger := e.newCustomer(t, "theirs")

	list, err := e.svc.List(context.Background(), e.user, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != newer.ID || list[1].ID != older.ID || list[0].Findings != 2 {
		t.Errorf("list = %+v, want %s then %s", list, newer.ID, older.ID)
	}
	if theirs, err := e.svc.List(context.Background(), stranger, 0); err != nil || len(theirs) != 0 {
		t.Errorf("another Customer's list = %+v, %v", theirs, err)
	}
	_, err = e.svc.Latest(context.Background(), stranger)
	wantErr(t, err, agents.ErrPrioritizationNotFound)
	for _, limit := range []int{-1, agents.MaxLimit + 1} {
		_, err := e.svc.List(context.Background(), e.user, limit)
		wantErr(t, err, agents.ErrInvalidLimit)
	}
}

func TestGetShowsEachOpenFindingAsItIsNow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	moved := score(0.85)
	moved.Factors.LifecycleMultiplier = 0.8
	e.rescore(t, e.pg(), moved)
	err := e.db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.CloseFinding(context.Background(), finding.ID(uuid.MustParse(e.os())), finding.ComponentRemoved)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := e.svc.Get(context.Background(), e.user, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	placed, _ := got.Finding(e.pg())
	current, ok := got.Current[e.pg()]
	if !ok || current.Score.Value != 0.85 || current.Score.LifecycleMultiplier != 0.8 || current.Asset.Name != "pg-prod-01" {
		t.Errorf("current = %+v, %v, want the Score as it is now", current, ok)
	}
	if placed.Score.Value != 0.9 {
		t.Errorf("placed score = %+v, want it as it was placed", placed.Score)
	}
	if _, ok := got.Current[e.os()]; ok {
		t.Error("a closed Finding has a Current")
	}
}

func TestPlanRunsLunaOnTheFindingAsItIsNow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	e.rescore(t, e.pg(), score(0.95))
	e.llm.Queue(claudetest.JSON(t, validPlan()))

	plan, err := e.svc.Plan(context.Background(), e.user, p.ID, e.pg())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Finding != e.pg() || plan.Created.IsZero() || plan.Luna.Status != agents.Verified {
		t.Errorf("plan = %+v", plan)
	}
	contains(t, prompt(e.llm.Requests()[1]), `"value": 0.95`)

	newer := validPlan()
	newer.Summary = "Segunda versión del plan de PostgreSQL 15.6."
	e.llm.Queue(claudetest.JSON(t, newer))
	if _, err := e.svc.Plan(context.Background(), e.user, p.ID, e.pg()); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.Get(context.Background(), e.user, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	stored, ok := got.PlanOf(e.pg())
	if len(got.Plans) != 1 || !ok || stored.Luna.Output.Summary != newer.Summary || stored.Created.IsZero() {
		t.Errorf("plans = %+v, want only the newest", got.Plans)
	}
	if stored.Dossier.Finding != e.pg() || stored.Dossier.Score.Value != 0.95 {
		t.Errorf("plan dossier = %+v, want the one Luna read", stored.Dossier)
	}
	if _, ok := got.PlanOf(e.os()); ok {
		t.Error("a Finding nobody asked a plan for has one")
	}
}

func TestPlanStoresNothingWithoutAVerifiedAnswer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	e.llm.Queue(claudetest.Fail(http.StatusUnauthorized))

	_, err := e.svc.Plan(context.Background(), e.user, p.ID, e.pg())

	wantErr(t, err, agents.ErrUnavailable)
	got, err := e.svc.Get(context.Background(), e.user, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Plans) != 0 {
		t.Errorf("plans = %+v, want none", got.Plans)
	}
}

func TestPlanRefusesBeforeCallingTheModel(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	stranger := e.newCustomer(t, "theirs")
	calls := len(e.llm.Requests())

	_, err := e.svc.Plan(context.Background(), stranger, p.ID, e.pg())
	wantErr(t, err, agents.ErrPrioritizationNotFound)
	_, err = e.svc.Plan(context.Background(), e.user, p.ID, "f-9")
	wantErr(t, err, agents.ErrFindingNotFound)
	_, err = e.svc.Plan(context.Background(), e.user, p.ID, uuid.NewString())
	wantErr(t, err, agents.ErrFindingNotFound)

	if len(e.llm.Requests()) != calls {
		t.Error("the model was called")
	}
}

func TestFeedbackIsKeptOnTheFinding(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)

	stored, err := e.svc.RecordFeedback(context.Background(), e.user, p.ID, e.os(), "should_be_earlier", "es el servidor de pagos")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Author != e.user.ID() || stored.ViaAnalista || stored.Created.IsZero() || stored.Finding.String() != e.os() {
		t.Errorf("feedback = %+v", stored)
	}

	got, err := e.svc.Get(context.Background(), e.user, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Feedback) != 1 || got.Feedback[0].Verdict.Code() != "should_be_earlier" || got.Feedback[0].Finding.String() != e.os() {
		t.Errorf("feedback = %+v", got.Feedback)
	}
}

func TestOnlyFeedbackOnTheOrderNotifies(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	notices := 0
	e.svc.OnOrderFeedback(func() { notices++ })

	for _, verdict := range []string{"applies", "does_not_apply", "remediated", "should_be_earlier", "should_be_later"} {
		if _, err := e.svc.RecordFeedback(context.Background(), e.user, p.ID, e.os(), verdict, ""); err != nil {
			t.Fatal(err)
		}
	}

	if notices != 2 {
		t.Errorf("notices = %d, want one for each verdict on the order", notices)
	}
}

func TestRecordFeedbackRejects(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	stranger := e.newCustomer(t, "theirs")
	record := func(id uuid.UUID, finding, verdict, note string) error {
		_, err := e.svc.RecordFeedback(context.Background(), e.user, id, finding, verdict, note)
		return err
	}

	wantErr(t, record(p.ID, e.pg(), "maybe", ""), agents.ErrInvalidFeedback)
	wantErr(t, record(p.ID, e.pg(), "applies", strings.Repeat("x", agents.MaxNoteLength+1)), agents.ErrInvalidFeedback)
	wantErr(t, record(p.ID, "f-9", "applies", ""), agents.ErrFindingNotFound)
	wantErr(t, record(p.ID, uuid.NewString(), "applies", ""), agents.ErrFindingNotFound)
	wantErr(t, record(uuid.New(), e.pg(), "applies", ""), agents.ErrPrioritizationNotFound)
	_, err := e.svc.RecordFeedback(context.Background(), stranger, p.ID, e.pg(), "applies", "")
	wantErr(t, err, agents.ErrPrioritizationNotFound)
	_, err = e.svc.Get(context.Background(), stranger, p.ID)
	wantErr(t, err, agents.ErrPrioritizationNotFound)
	if err := record(p.ID, e.pg(), "applies", strings.Repeat("ñ", agents.MaxNoteLength)); err != nil {
		t.Errorf("a note at the limit, in accented text: err = %v", err)
	}
}
