package agents_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"barbackend/internal/agents"
	"barbackend/internal/claude/claudetest"
	"barbackend/internal/finding"
	"barbackend/internal/postgres"
	"github.com/google/uuid"
)

// planAll runs Luna on her own, answering each request with the next of
// replies, and returns what she did.
func (e env) planAll(t *testing.T, replies ...claudetest.Reply) agents.PlanningRun {
	t.Helper()
	e.llm.Queue(replies...)
	run, err := e.svc.PlanAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return run
}

// planned is the Finding whose Dossier Luna was asked about in the request
// of that index.
func (e env) planned(t *testing.T, request int) string {
	t.Helper()
	return section(t, prompt(e.llm.Requests()[request]), "dossier")
}

// otherCustomer is another Customer with its own Asset, Findings and
// Prioritization, in the same database and with the same model.
func (e env) otherCustomer(t *testing.T, assetName string) env {
	t.Helper()
	other := e
	other.user, other.source = e.newCustomerWithSource(t, assetName)
	var err error
	if other.customer, err = other.user.ActsFor(); err != nil {
		t.Fatal(err)
	}
	other.found = &storedFindings{}
	other.prioritize(t)
	return other
}

func TestLunaPlansEachOpenFindingOnHerOwnInTheOrderOfThePrioritization(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	plan := claudetest.JSON(t, validPlan())

	if run := e.planAll(t, plan, plan); run != (agents.PlanningRun{Planned: 2}) {
		t.Errorf("run = %+v, want both Findings planned", run)
	}
	contains(t, e.planned(t, 1), e.pg())
	contains(t, e.planned(t, 2), e.os())
	got, err := e.svc.Get(context.Background(), e.user, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{e.pg(), e.os()} {
		if stored, ok := got.PlanOf(id); !ok || stored.Luna.Status != agents.Verified || stored.Dossier.Finding != id || stored.Created.IsZero() {
			t.Errorf("plan of %s = %+v, want Luna's with the Dossier she read", id, stored)
		}
	}

	if run := e.planAll(t); run != (agents.PlanningRun{}) || len(e.llm.Requests()) != 3 {
		t.Errorf("second run = %+v after %d requests, want nothing due", run, len(e.llm.Requests()))
	}
}

func TestLunaLeavesAFindingWhosePlanAUserAskedFor(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	e.llm.Queue(claudetest.JSON(t, validPlan()))
	if _, err := e.svc.Plan(context.Background(), e.user, p.ID, e.pg()); err != nil {
		t.Fatal(err)
	}

	if run := e.planAll(t, claudetest.JSON(t, validPlan())); run != (agents.PlanningRun{Planned: 1}) {
		t.Errorf("run = %+v, want only the Finding without a plan", run)
	}
	contains(t, e.planned(t, 2), e.os())
}

func TestLunaPlansAgainOnlyAFindingThatChangedSinceItsPlan(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.prioritize(t)
	plan := claudetest.JSON(t, validPlan())
	e.planAll(t, plan, plan)
	e.rescore(t, e.pg(), score(0.5))
	e.rescore(t, e.os(), score(0.65))

	if run := e.planAll(t, plan); run != (agents.PlanningRun{Planned: 1}) || len(e.llm.Requests()) != 4 {
		t.Errorf("run = %+v after %d requests, want only the Finding whose Score moved by 0.1 or more", run, len(e.llm.Requests()))
	}
	asked := e.planned(t, 3)
	contains(t, asked, e.pg())
	contains(t, asked, `"value": 0.5`)
}

func TestLunaLeavesAClosedFinding(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.prioritize(t)
	err := e.db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.CloseFinding(context.Background(), finding.ID(uuid.MustParse(e.os())), finding.ComponentRemoved)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	if run := e.planAll(t, claudetest.JSON(t, validPlan())); run != (agents.PlanningRun{Planned: 1}) || len(e.llm.Requests()) != 2 {
		t.Errorf("run = %+v after %d requests, want only the open Finding planned", run, len(e.llm.Requests()))
	}
	contains(t, e.planned(t, 1), e.pg())
}

func TestAFailedPlanIsTriedInLaterRunsUpToThreeTimesAsOnePlacement(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.prioritize(t)
	if run := e.planAll(t, claudetest.Refusal(), claudetest.JSON(t, validPlan())); run != (agents.PlanningRun{Planned: 1, Failed: 1}) {
		t.Errorf("first run = %+v, want PostgreSQL failed once and Ubuntu planned", run)
	}
	for range 2 {
		if run := e.planAll(t, claudetest.Refusal()); run != (agents.PlanningRun{Failed: 1}) {
			t.Errorf("run = %+v, want PostgreSQL tried once more", run)
		}
	}

	if run := e.planAll(t); run != (agents.PlanningRun{}) || len(e.llm.Requests()) != 5 {
		t.Errorf("fourth run = %+v after %d requests, want nothing: no attempts left", run, len(e.llm.Requests()))
	}

	e.rescore(t, e.pg(), score(0.3))
	e.prioritizeWith(t, placement(standing(1), newGroup("Ya no tan urgente", e.pg(), "PostgreSQL 15.6 bajó.", pgEvidence(e))))
	if run := e.planAll(t, claudetest.JSON(t, validPlan())); run != (agents.PlanningRun{Planned: 1}) {
		t.Errorf("run = %+v, want a Finding placed again tried anew", run)
	}
}

func TestAModelThatCannotBeCalledStopsLunaAndSpendsNoAttempt(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.prioritize(t)
	for range 3 {
		e.llm.Queue(claudetest.Fail(http.StatusUnauthorized))
		run, err := e.svc.PlanAll(context.Background())
		if !errors.Is(err, agents.ErrUnavailable) || run != (agents.PlanningRun{}) {
			t.Errorf("run = %+v, err = %v, want ErrUnavailable and nothing done", run, err)
		}
	}
	if n := len(e.llm.Requests()); n != 4 {
		t.Errorf("%d requests, want each run stopped after its first", n)
	}

	plan := claudetest.JSON(t, validPlan())
	if run := e.planAll(t, plan, plan); run != (agents.PlanningRun{Planned: 2}) {
		t.Errorf("run = %+v, want both planned: an outage is not a Finding's failure", run)
	}
}

func TestLunaPlansForEveryActiveCustomer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.prioritize(t)
	other := e.otherCustomer(t, "theirs")
	gone := e.otherCustomer(t, "gone")
	err := e.db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.DeactivateCustomer(context.Background(), gone.customer)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := claudetest.JSON(t, validPlan())

	if run := e.planAll(t, plan, plan, plan, plan); run != (agents.PlanningRun{Planned: 4}) || len(e.llm.Requests()) != 7 {
		t.Errorf("run = %+v after %d requests, want the Findings of both active Customers planned", run, len(e.llm.Requests()))
	}
	for _, c := range []env{e, other} {
		if got := c.latest(t); len(got.Plans) != 2 {
			t.Errorf("plans of %s = %+v, want both", c.customer, got.Plans)
		}
	}
}
