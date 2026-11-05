package agents_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"barbackend/internal/agents"
	"barbackend/internal/claude/claudetest"
	"github.com/google/uuid"
)

func TestPrioritizeStoresThePrioritization(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	created := e.prioritize(t)

	if created.ID == uuid.Nil || created.Created.IsZero() {
		t.Errorf("prioritization = %+v", created)
	}
	got, err := e.svc.Get(context.Background(), e.user, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 2 || got.Prioritizer.Status != agents.Verified || got.GroupOf(osFind) != 2 || got.Findings[0].Asset.Name != "pg-prod-01" {
		t.Errorf("stored prioritization = %+v", got)
	}
	list, err := e.svc.List(context.Background(), e.user, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != created.ID || list[0].Findings != 2 || list[0].Groups != 2 {
		t.Errorf("list = %+v", list)
	}
}

func TestPrioritizeStoresNothingWithoutAVerifiedAnswer(t *testing.T) {
	t.Parallel()
	leftOut := validList()
	leftOut.Groups = leftOut.Groups[:1]
	tests := []struct {
		name    string
		replies []claudetest.Reply
		want    error
	}{
		{"failed", []claudetest.Reply{claudetest.Fail(http.StatusUnauthorized)}, agents.ErrUnavailable},
		{"refused", []claudetest.Reply{claudetest.Refusal()}, agents.ErrRefused},
		{"rejected twice", []claudetest.Reply{claudetest.JSON(t, leftOut), claudetest.JSON(t, leftOut)}, agents.ErrRejected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.llm.Queue(tt.replies...)

			_, err := e.svc.Prioritize(context.Background(), e.customer, findings(t))
			wantErr(t, err, tt.want)

			list, err := e.svc.List(context.Background(), e.user, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(list) != 0 {
				t.Errorf("list = %+v, want nothing stored", list)
			}
		})
	}
}

func TestListShowsTheCustomersNewestFirst(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	older := e.prioritize(t)
	newer := e.prioritize(t)
	stranger := e.newCustomer(t, "theirs")

	list, err := e.svc.List(context.Background(), e.user, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != newer.ID || list[1].ID != older.ID {
		t.Errorf("list = %+v, want %s then %s", list, newer.ID, older.ID)
	}
	latest, err := e.svc.Latest(context.Background(), e.user)
	if err != nil || latest.ID != newer.ID {
		t.Errorf("latest = %s, %v, want %s", latest.ID, err, newer.ID)
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

func TestPlanStoresLunasPlanForTheFinding(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	e.llm.Queue(claudetest.JSON(t, validPlan()))

	plan, err := e.svc.Plan(context.Background(), e.user, p.ID, pgFind)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Finding != pgFind || plan.Created.IsZero() || plan.Luna.Status != agents.Verified {
		t.Errorf("plan = %+v", plan)
	}

	newer := validPlan()
	newer.Summary = "Segunda versión del plan de PostgreSQL 15.6."
	e.llm.Queue(claudetest.JSON(t, newer))
	if _, err := e.svc.Plan(context.Background(), e.user, p.ID, pgFind); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.Get(context.Background(), e.user, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	stored, ok := got.PlanOf(pgFind)
	if len(got.Plans) != 1 || !ok || stored.Luna.Output.Summary != newer.Summary {
		t.Errorf("plans = %+v, want only the newest", got.Plans)
	}
	if _, ok := got.PlanOf(osFind); ok {
		t.Error("a Finding nobody asked a plan for has one")
	}
}

func TestPlanStoresNothingWithoutAVerifiedAnswer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	e.llm.Queue(claudetest.Fail(http.StatusUnauthorized))

	_, err := e.svc.Plan(context.Background(), e.user, p.ID, pgFind)

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

	_, err := e.svc.Plan(context.Background(), stranger, p.ID, pgFind)
	wantErr(t, err, agents.ErrPrioritizationNotFound)
	_, err = e.svc.Plan(context.Background(), e.user, p.ID, "f-9")
	wantErr(t, err, agents.ErrFindingNotFound)

	if len(e.llm.Requests()) != calls {
		t.Error("the model was called")
	}
}

func TestFeedbackIsKeptOnTheFinding(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)

	stored, err := e.svc.RecordFeedback(context.Background(), e.user, p.ID, osFind, "should_be_earlier", "es el servidor de pagos")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Author != e.user.ID() || stored.ViaAnalista || stored.Created.IsZero() || stored.Finding != osFind {
		t.Errorf("feedback = %+v", stored)
	}

	got, err := e.svc.Get(context.Background(), e.user, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Feedback) != 1 || got.Feedback[0].Verdict.Code() != "should_be_earlier" || got.Feedback[0].Finding != osFind {
		t.Errorf("feedback = %+v", got.Feedback)
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

	wantErr(t, record(p.ID, pgFind, "maybe", ""), agents.ErrInvalidFeedback)
	wantErr(t, record(p.ID, pgFind, "applies", strings.Repeat("x", agents.MaxNoteLength+1)), agents.ErrInvalidFeedback)
	wantErr(t, record(p.ID, "f-9", "applies", ""), agents.ErrFindingNotFound)
	wantErr(t, record(uuid.New(), pgFind, "applies", ""), agents.ErrPrioritizationNotFound)
	_, err := e.svc.RecordFeedback(context.Background(), stranger, p.ID, pgFind, "applies", "")
	wantErr(t, err, agents.ErrPrioritizationNotFound)
	_, err = e.svc.Get(context.Background(), stranger, p.ID)
	wantErr(t, err, agents.ErrPrioritizationNotFound)
	if err := record(p.ID, pgFind, "applies", strings.Repeat("ñ", agents.MaxNoteLength)); err != nil {
		t.Errorf("a note at the limit, in accented text: err = %v", err)
	}
}
