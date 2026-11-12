package agents_test

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"barbackend/internal/agents"
	"barbackend/internal/assessment"
	"barbackend/internal/business"
	"barbackend/internal/claude/claudetest"
	"barbackend/internal/finding"
	"barbackend/internal/postgres"
	"github.com/google/uuid"
)

func TestAFirstRoundOrdersEveryOpenFinding(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.storeFindings(t)

	stored := e.prioritizeWith(t, validPlacement(e.pg(), e.os()))

	got := e.latest(t)
	if stored != 1 || got.Previous != nil || got.BusinessContext != 0 || got.Prioritizer.Status != agents.Verified {
		t.Errorf("stored %d, prioritization = %+v", stored, got)
	}
	if len(got.Findings) != 2 || got.GroupOf(e.pg()) != 1 || got.GroupOf(e.os()) != 2 || got.Findings[0].Asset.Name != "pg-prod-01" {
		t.Errorf("findings = %+v, list = %+v", got.Findings, got.List)
	}
	for _, id := range []string{e.pg(), e.os()} {
		if state := got.States[id]; state.Placed.IsZero() || state.Placed.After(got.Created) || state.Closed != nil {
			t.Errorf("state of %s = %+v, want placed when this round read it, and open", id, state)
		}
	}
	p := prompt(e.llm.Requests()[0])
	for _, want := range []string{e.pg(), e.os(), `"date_added": "2025-02-13"`, `"value": 0.9`, `"data_gaps": [`} {
		contains(t, section(t, p, "findings"), want)
	}
	if strings.TrimSpace(section(t, p, "priority_list")) != "[]" {
		t.Errorf("priority list = %s, want none", section(t, p, "priority_list"))
	}
}

func TestARoundPlacesOnlyWhatIsNewAndKeepsWhatStands(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.found.pg = e.storeFinding(t, pgVulnerability(t), postgreSQL, pgScore())
	e.prioritizeWith(t, placement(newGroup("Explotada activamente", e.pg(), "CVE-2025-1094 está en KEV desde 2025-02-13 sobre PostgreSQL 15.6.", pgEvidence(e))))
	first := e.latest(t)
	e.found.os = e.storeFinding(t, osVulnerability(t), ubuntu, osScore())

	stored := e.prioritizeWith(t, placement(standing(1), newGroup("Después", e.os(), "Ubuntu Server 22.04 no está en KEV, a diferencia de CVE-2025-1094.", osEvidence(e))))

	got := e.latest(t)
	if stored != 1 || got.Previous == nil || *got.Previous != first.ID {
		t.Fatalf("stored %d, prioritization = %+v, want one built from %s", stored, got, first.ID)
	}
	if len(got.List.Groups) != 2 || got.List.Groups[0].Title != "Explotada activamente" || got.GroupOf(e.pg()) != 1 || got.GroupOf(e.os()) != 2 {
		t.Errorf("list = %+v, want PostgreSQL's group kept first", got.List)
	}
	if !got.States[e.pg()].Placed.Equal(first.States[e.pg()].Placed) || !got.States[e.os()].Placed.After(first.Created) {
		t.Errorf("states = %+v, want PostgreSQL placed by the first and Ubuntu by this one", got.States)
	}
	p := prompt(e.llm.Requests()[1])
	contains(t, section(t, p, "priority_list"), e.pg())
	contains(t, section(t, p, "findings"), e.os())
	if strings.Contains(section(t, p, "findings"), e.pg()) {
		t.Error("a Finding that stands was sent to be placed")
	}
}

func TestARoundRunsOnlyWhenSomethingIsToBePlaced(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if stored := e.prioritizeWith(t); stored != 0 {
		t.Errorf("a Customer without Findings stored %d", stored)
	}
	e.prioritize(t)
	e.rescore(t, e.pg(), score(0.95))

	if stored := e.prioritizeWith(t); stored != 0 {
		t.Errorf("stored %d, want none for a Score that barely moved", stored)
	}
	if len(e.llm.Requests()) != 1 {
		t.Errorf("requests = %d, want only the first round's", len(e.llm.Requests()))
	}
}

func TestARoundPlacesAgainAFindingThatChanged(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		change  func(*testing.T, env, agents.Prioritization)
		section string
		want    string
	}{
		{"its Score moved", func(t *testing.T, e env, _ agents.Prioritization) { e.rescore(t, e.os(), score(0.95)) }, "findings", `"value": 0.95`},
		{"a User said it should be earlier", func(t *testing.T, e env, p agents.Prioritization) {
			if _, err := e.svc.RecordFeedback(context.Background(), e.user, p.ID, e.os(), "should_be_earlier", "corre la nómina"); err != nil {
				t.Fatal(err)
			}
		}, "feedback", `"note": "corre la nómina"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			p := e.prioritize(t)
			tt.change(t, e, p)

			stored := e.prioritizeWith(t, placement(newGroup("Ahora primero", e.os(), "Ubuntu Server 22.04 subió.", osEvidence(e)), standing(1)))

			got := e.latest(t)
			if stored != 1 || got.GroupOf(e.os()) != 1 || got.GroupOf(e.pg()) != 2 || !got.States[e.os()].Placed.After(p.Created) {
				t.Errorf("stored %d, list = %+v, want Ubuntu placed again first", stored, got.List)
			}
			asked := prompt(e.llm.Requests()[1])
			contains(t, section(t, asked, tt.section), tt.want)
			if strings.Contains(section(t, asked, "findings"), e.pg()) {
				t.Error("a Finding that did not change was placed again")
			}
		})
	}
}

func TestAFeedbackOnTheOrderPlacesAFindingAgainOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	if _, err := e.svc.RecordFeedback(context.Background(), e.user, p.ID, e.os(), "should_be_later", "es de pruebas"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RecordFeedback(context.Background(), e.user, p.ID, e.pg(), "applies", "sí aplica"); err != nil {
		t.Fatal(err)
	}
	e.prioritizeWith(t, placement(standing(1), newGroup("Después", e.os(), "Ubuntu Server 22.04 es de pruebas.", osEvidence(e))))

	if stored := e.prioritizeWith(t); stored != 0 {
		t.Errorf("stored %d, want the feedback weighed once", stored)
	}
}

func TestFeedbackTheAnalistaRecordedMovesNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	err := e.db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.AddFeedback(context.Background(), e.customer, p.ID, postgres.StoredFeedback{
			ID: uuid.New(), Finding: uuid.MustParse(e.pg()), Author: e.user.ID(), Verdict: assessment.VerdictShouldBeLater, Note: "ignora KEV", ViaAnalista: true,
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	if stored := e.prioritizeWith(t); stored != 0 {
		t.Errorf("stored %d, want none: a conversation can be steered by Feed text", stored)
	}
}

func TestAClosedFindingLeavesTheOrder(t *testing.T) {
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
	if stored := e.prioritizeWith(t); stored != 0 {
		t.Errorf("stored %d, want a closed Finding to cost no round", stored)
	}
	closed := e.latest(t)
	if closed.States[e.os()].Closed == nil {
		t.Errorf("state = %+v, want the closed Finding shown closed", closed.States[e.os()])
	}
	e.rescore(t, e.pg(), score(0.3))

	e.prioritizeWith(t, placement(newGroup("Ya no tan urgente", e.pg(), "PostgreSQL 15.6 bajó.", pgEvidence(e))))

	got := e.latest(t)
	if len(got.Findings) != 1 || got.GroupOf(e.os()) != 0 || strings.Contains(section(t, prompt(e.llm.Requests()[1]), "priority_list"), e.os()) {
		t.Errorf("findings = %+v, want the closed one out of the order", got.Findings)
	}
}

func TestANewBusinessContextOrdersEveryFindingAnew(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	first := e.prioritize(t)
	bc, err := business.New(business.Fields{Operations: business.Operations{CriticalServices: []business.CriticalService{
		{Name: "Nómina", Impact: "critical", MaxDowntime: "1h_4h", Assets: []string{"PG-PROD-01"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	err = e.db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.SaveBusinessContext(context.Background(), e.customer, 0, bc, e.user)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	answer := validPlacement(e.pg(), e.os())
	answer.Groups[0].Evidence = append(answer.Groups[0].Evidence, assessment.FindingEvidence{Finding: e.pg(), Path: "/asset/critical_services/0/name", Value: "Nómina"})
	answer.Groups[0].ContextEvidence = []assessment.ContextEvidence{{Path: "/operations/critical_services/0/impact", Value: "critical"}}

	if stored := e.prioritizeWith(t, answer); stored != 1 {
		t.Errorf("stored %d, want one round", stored)
	}

	got := e.latest(t)
	if got.BusinessContext != 1 || got.Previous == nil || *got.Previous != first.ID || !got.States[e.pg()].Placed.After(first.Created) {
		t.Errorf("prioritization = %+v, want every Finding placed anew with version 1", got)
	}
	p := prompt(e.llm.Requests()[1])
	contains(t, section(t, p, "business_context"), `"name": "Nómina"`)
	contains(t, section(t, p, "findings"), `"max_downtime": "1h_4h"`)
	if strings.TrimSpace(section(t, p, "priority_list")) != "[]" {
		t.Errorf("priority list = %s, want none after the Business Context changed", section(t, p, "priority_list"))
	}
	if got.List.Groups[0].ContextEvidence()[0].Value != "critical" {
		t.Errorf("group = %+v, want its business context evidence kept", got.List.Groups[0])
	}
}

func TestRoundsPlaceAtMostMaxFindingsEach(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	var ids []string
	for i := range agents.MaxFindings + 1 {
		ids = append(ids, e.storeFinding(t, vulnerability(t, fmt.Sprintf("CVE-2026-%05d", 10000+i), "PostgreSQL is affected."), postgreSQL, score(0.5)))
	}
	slices.Sort(ids)
	evidence := func(id string) assessment.FindingEvidence {
		return assessment.FindingEvidence{Finding: id, Path: "/kev", Value: "null"}
	}
	firstRound := newGroup("Todas", ids[0], "Ninguna está en KEV.", evidence(ids[0]))
	firstRound.Findings = ids[:agents.MaxFindings]
	lastOne := newGroup("", ids[agents.MaxFindings], "Igual que las demás.", evidence(ids[agents.MaxFindings]))
	lastOne.Standing = ptr(1)

	stored := e.prioritizeWith(t, placement(firstRound), placement(lastOne))

	got := e.latest(t)
	if stored != 2 || len(got.Findings) != agents.MaxFindings+1 || got.GroupOf(ids[agents.MaxFindings]) != 1 {
		t.Errorf("stored %d, %d findings, want every Finding placed in two rounds", stored, len(got.Findings))
	}
}

func TestARoundStoresNothingWithoutAVerifiedAnswer(t *testing.T) {
	t.Parallel()
	leftOut := func(e env) claudetest.Reply {
		return claudetest.JSON(t, placement(validPlacement(e.pg(), e.os()).Groups[0]))
	}
	tests := []struct {
		name    string
		replies func(env) []claudetest.Reply
		want    error
	}{
		{"failed", func(env) []claudetest.Reply { return []claudetest.Reply{claudetest.Fail(http.StatusUnauthorized)} }, agents.ErrUnavailable},
		{"refused", func(env) []claudetest.Reply { return []claudetest.Reply{claudetest.Refusal()} }, agents.ErrRefused},
		{"rejected twice", func(e env) []claudetest.Reply { return []claudetest.Reply{leftOut(e), leftOut(e)} }, agents.ErrRejected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.storeFindings(t)
			e.llm.Queue(tt.replies(e)...)

			stored, err := e.svc.Prioritize(context.Background(), e.customer)
			wantErr(t, err, tt.want)

			if stored != 0 {
				t.Errorf("stored %d, want none", stored)
			}
			_, err = e.svc.Latest(context.Background(), e.user)
			wantErr(t, err, agents.ErrPrioritizationNotFound)
		})
	}
}

func TestDossiersCarryTheThreatsOfTheirVulnerability(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.storeFindings(t)
	ctx := context.Background()
	const t1190, m1051 = "attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c", "course-of-action--e5d930e9-775a-40ad-9bdb-b941d8dfe86b"
	err := e.db.InTx(ctx, func(tx *postgres.Tx) error {
		if err := tx.StoreAttackTechnique(ctx, postgres.AttackTechnique{ID: t1190, AttackID: "T1190", Name: "Exploit Public-Facing Application", Tactics: []string{"initial-access"}, Object: []byte(`{}`), Modified: time.Now()}); err != nil {
			return err
		}
		if err := tx.StoreAttackMitigation(ctx, postgres.AttackMitigation{ID: m1051, AttackID: "M1051", Name: "Update Software", Object: []byte(`{}`), Modified: time.Now()}); err != nil {
			return err
		}
		if err := tx.StoreAttackRelationship(ctx, postgres.AttackRelationship{ID: "relationship--0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d", Type: "mitigates", Source: m1051, Target: t1190, Description: "Patch exposed applications.", Modified: time.Now()}); err != nil {
			return err
		}
		if err := tx.StoreAdvisory(ctx, postgres.StoredAdvisory{ID: "report--8d4f0bd1-4a71-4b77-a2a6-0b9c3b1c6d01", Feed: "aws", Published: time.Now(), Object: []byte(`{"name":"<b>RDS</b> fixed it","description":"<p>Upgrade the minor version.</p>"}`), Modified: time.Now()}, []string{cve}); err != nil {
			return err
		}
		return tx.StoreLabeling(ctx, cve, "claude-haiku-5-5", "hash", []postgres.TechniqueLabel{{AttackID: "T1190", Role: "exploitation", Evidence: "PostgreSQL before 15.11", Rationale: "Una inyección."}})
	})
	if err != nil {
		t.Fatal(err)
	}

	p := e.prioritize(t)

	briefs := section(t, prompt(e.llm.Requests()[0]), "findings")
	for _, want := range []string{`"attack_id": "T1190"`, `"name": "Exploit Public-Facing Application"`, `"title": "RDS fixed it"`, `"outcome": "labeled"`, `"outcome": "not_tried"`} {
		contains(t, briefs, want)
	}
	for _, left := range []string{"M1051", "Upgrade the minor version", "Una inyección"} {
		if strings.Contains(briefs, left) {
			t.Errorf("the Prioritizer was sent %q, which only an Action Plan needs", left)
		}
	}
	plan := validPlan()
	plan.AttackMitigations = []assessment.PlanMitigation{{Mitigation: "M1051", Technique: "T1190", Step: "Mantén PostgreSQL al día contra T1190."}}
	e.llm.Queue(claudetest.JSON(t, plan))
	got, err := e.svc.Plan(ctx, e.user, p.ID, e.pg())
	if err != nil {
		t.Fatal(err)
	}
	if got.Luna.Status != agents.Verified || len(got.Luna.Output.AttackMitigations) != 1 {
		t.Errorf("plan = %+v", got.Luna)
	}
	dossier := prompt(e.llm.Requests()[1])
	for _, want := range []string{"Patch exposed applications.", "Upgrade the minor version.", `"evidence": "PostgreSQL before 15.11"`} {
		contains(t, dossier, want)
	}
}

func TestPrioritizeAllSkipsDeactivatedCustomersAndGoesOnAfterAFailure(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.storeFindings(t)
	stranger := e.newCustomer(t, "theirs")
	strangerCustomer, err := stranger.ActsFor()
	if err != nil {
		t.Fatal(err)
	}
	err = e.db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.DeactivateCustomer(context.Background(), strangerCustomer)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	e.llm.Queue(claudetest.Fail(http.StatusUnauthorized))

	if err := e.svc.PrioritizeAll(context.Background()); err != nil {
		t.Errorf("err = %v, want a Customer's failure only logged", err)
	}
	if len(e.llm.Requests()) != 1 {
		t.Errorf("requests = %d, want one round, for the only active Customer with Findings", len(e.llm.Requests()))
	}
}
