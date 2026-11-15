package agents_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"barbackend/internal/agents"
	"barbackend/internal/alert"
	"barbackend/internal/assessment"
	"barbackend/internal/business"
	"barbackend/internal/claude/claudetest"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/scoring"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// delivery is a queued Slack delivery as a test reads it.
type delivery struct {
	kind, targetKind, target string
	finding                  *uuid.UUID
	payload                  []byte
}

// deliveries are the Customer's queued Slack deliveries in the order the
// worker claims each target's.
func (e env) deliveries(t *testing.T) []delivery {
	t.Helper()
	rows, err := pgtest.Conn(t, e.url).Query(context.Background(), `
		SELECT kind, target_kind, target, finding_id, payload FROM slack_deliveries
		WHERE customer_id = $1 ORDER BY created_at, id`, uuid.UUID(e.customer))
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (delivery, error) {
		var d delivery
		return d, row.Scan(&d.kind, &d.targetKind, &d.target, &d.finding, &d.payload)
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func decode[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// banded is a Model 3 Score of a Finding of a CVE of that CVSS, listed in KEV
// or not, on a High, Internet-facing, Production and Confidential Asset: half
// the CVSS outside KEV, all of it in KEV, so CVSS 6 is Medium outside KEV and
// High in it.
func banded(t *testing.T, cvss float64, kev bool) scoring.Score {
	t.Helper()
	s, err := scoring.Model3.Compute(scoring.Inputs{
		CVSS: &cvss, EPSS: ptr(0.0), KEVListed: kev,
		Criticality: inventory.CriticalityHigh, Exposure: inventory.InternetFacing,
		Lifecycle: inventory.LifecycleProduction, Classification: inventory.ClassifiedConfidential,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTheFirstRoundAlertsInBatchesAsTheInitialLoad(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	p := e.prioritize(t)

	got := e.deliveries(t)
	if len(got) != 2 || got[0].targetKind != "channel" || got[0].target != alert.SecurityTeam || got[1].targetKind != "email" || got[1].target != owner {
		t.Fatalf("deliveries = %+v, want one batch to the channel and one to the owner", got)
	}
	for _, d := range got {
		b := decode[alert.Batch](t, d.payload)
		if d.kind != alert.KindBatch || d.finding != nil || len(b.Findings) != 2 || b.Findings[0].Finding != e.pg() || b.Findings[1].Finding != e.os() {
			t.Errorf("delivery = %+v with %+v, want a batch naming no Finding, PostgreSQL's first by Score", d, b)
		}
	}
	if p.InitialLoad {
		t.Error("the Initial Load goes on after a round that left nothing to place")
	}
}

func TestAfterTheInitialLoadANewFindingIsAlertedAlone(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	first := e.prioritize(t)
	queued := len(e.deliveries(t))
	newer := e.storeFinding(t, vulnerability(t, "CVE-2026-0001", "PostgreSQL is affected."), postgreSQL, score(0.7))

	e.prioritizeWith(t, placement(standing(1), newGroup("Después de Ubuntu", newer, "No está en KEV, como Ubuntu.", assessment.FindingEvidence{Finding: newer, Path: "/kev", Value: "null"}), standing(2)))

	got := e.deliveries(t)[queued:]
	if len(got) != 2 || got[0].targetKind != alert.TargetEmail || got[0].target != owner || got[1].targetKind != alert.TargetChannel || got[1].target != alert.SecurityTeam {
		t.Fatalf("deliveries = %+v, want one to the owner and one to the channel", got)
	}
	latest := e.latest(t)
	for _, d := range got {
		a := decode[alert.Finding](t, d.payload)
		if d.kind != alert.KindFinding || d.finding == nil || d.finding.String() != newer {
			t.Errorf("delivery = %+v, want one about %s", d, newer)
		}
		g := a.Group
		if a.Reason != alert.New || a.CVE != "CVE-2026-0001" || a.Asset != "pg-prod-01" || a.Component != "PostgreSQL 15.6" || a.OwnerEmail != owner || a.Prioritization != latest.ID.String() ||
			g.Position != 2 || g.Of != 3 || g.Title != "Después de Ubuntu" || !strings.HasPrefix(g.Reason, "No está en KEV, como Ubuntu.") {
			t.Errorf("alert = %+v, want a new one in group 2 of 3 of %s", a, latest.ID)
		}
	}
	if latest.ID == first.ID {
		t.Fatal("no round was stored")
	}
}

func TestARoundAlertsABandThatRoseAndNotOneThatFell(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.found.pg = e.storeFinding(t, pgVulnerability(t), postgreSQL, banded(t, 10, false))
	e.found.os = e.storeFinding(t, osVulnerability(t), ubuntu, banded(t, 6, false))
	e.prioritize(t)
	queued := len(e.deliveries(t))

	e.rescore(t, e.os(), banded(t, 6, true))
	e.prioritizeWith(t, placement(newGroup("Ahora primero", e.os(), "Ubuntu Server 22.04 subió.", osEvidence(e)), standing(1)))

	got := e.deliveries(t)[queued:]
	if len(got) != 2 {
		t.Fatalf("deliveries = %+v, want the rise to the channel and the owner", got)
	}
	if a := decode[alert.Finding](t, got[0].payload); a.Reason != alert.BandRose || a.BandWas != "medium" || a.Band != "high" || a.Finding != e.os() {
		t.Errorf("alert = %+v, want Ubuntu's Band risen from medium to high", a)
	}
	queued += len(got)

	e.rescore(t, e.os(), banded(t, 6, false))
	e.prioritizeWith(t, placement(standing(1), newGroup("Al final", e.os(), "Ubuntu Server 22.04 salió de KEV.", osEvidence(e))))

	if got := e.deliveries(t)[queued:]; len(got) != 0 {
		t.Errorf("deliveries = %+v, want none for a Band that fell", got)
	}
}

func TestTheInitialLoadLastsUntilEveryOpenFindingHasAPlace(t *testing.T) {
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

	// With one answer queued, the second round gets none and the run stops
	// after the first, as a run cut short does.
	e.llm.Queue(claudetest.JSON(t, placement(firstRound)))
	if stored, err := e.svc.Prioritize(context.Background(), e.customer); stored != 1 || !errors.Is(err, agents.ErrUnavailable) || !e.latest(t).InitialLoad {
		t.Fatalf("stored %d, %v, Initial Load %v; want one round, the second unanswered, and the load going on with a Finding still without a place", stored, err, e.latest(t).InitialLoad)
	}
	e.prioritizeWith(t, placement(lastOne))

	got := e.deliveries(t)
	var batches, findings int
	for _, d := range got {
		if d.kind == alert.KindBatch {
			batches += len(decode[alert.Batch](t, d.payload).Findings)
		} else {
			findings++
		}
	}
	if findings != 0 || batches != 2*(agents.MaxFindings+1) || e.latest(t).InitialLoad {
		t.Errorf("%d alerts in batches and %d alone, Initial Load %v; want every Finding batched twice and the load over", batches, findings, e.latest(t).InitialLoad)
	}
}

// allIn is one new group of the Findings of those ids, cited by the first.
func allIn(title string, ids ...string) assessment.PlacedGroup {
	g := newGroup(title, ids[0], "Ninguna está en KEV.", assessment.FindingEvidence{Finding: ids[0], Path: "/kev", Value: "null"})
	g.Findings = ids
	return g
}

func TestANewBusinessContextAlertsNothingEvenOverSeveralRounds(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	var ids []string
	for i := range agents.MaxFindings + 1 {
		ids = append(ids, e.storeFinding(t, vulnerability(t, fmt.Sprintf("CVE-2026-%05d", 10000+i), "PostgreSQL is affected."), postgreSQL, banded(t, 6, false)))
	}
	slices.Sort(ids)
	lastOne := allIn("", ids[agents.MaxFindings])
	lastOne.Standing = ptr(1)
	e.prioritizeWith(t, placement(allIn("Todas", ids[:agents.MaxFindings]...)), placement(lastOne))
	queued := len(e.deliveries(t))
	bc, err := business.New(business.Fields{Operations: business.Operations{CriticalServices: []business.CriticalService{
		{Name: "Nómina", Impact: "critical", MaxDowntime: "1h_4h", Assets: []string{"PG-PROD-01"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.SaveBusinessContext(context.Background(), e.customer, 0, bc, e.user)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if stored := e.prioritizeWith(t, placement(allIn("Todas", ids[:agents.MaxFindings]...)), placement(lastOne)); stored != 2 {
		t.Fatalf("stored %d, want the order made anew in two rounds", stored)
	}

	if got := e.deliveries(t)[queued:]; len(got) != 0 {
		t.Errorf("%d deliveries, want none for Findings placed before, at the same Band", len(got))
	}
}

func TestAFindingWithNoAssetOwnerStillGetsItsDMRow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.prioritize(t)
	queued := len(e.deliveries(t))
	ownerless := assetParams("pg-prod-01")
	ownerless.Owner = inventory.OwnerEmail{}
	e.sync(t, e.source, map[string]inventory.ImportedAssetParams{"1": ownerless})
	newer := e.storeFinding(t, vulnerability(t, "CVE-2026-0001", "PostgreSQL is affected."), postgreSQL, score(0.7))

	e.prioritizeWith(t, placement(standing(1), standing(2), allIn("Al final", newer)))

	got := e.deliveries(t)[queued:]
	if len(got) != 2 || got[0].targetKind != alert.TargetEmail || got[0].target != "" || got[1].target != alert.SecurityTeam {
		t.Fatalf("deliveries = %+v, want a DM row with no target and the channel's", got)
	}
}

func TestTheInitialLoadBatchesEachOwnersFindingsAndTheChannelsHighestScoreFirst(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	web := assetParams("web-01")
	web.Owner = mustOwner(t, "ops@example.com")
	e.sync(t, e.source, map[string]inventory.ImportedAssetParams{"1": assetParams("pg-prod-01"), "2": web})
	low := e.storeFindingOn(t, "1", vulnerability(t, "CVE-2026-0001", "PostgreSQL is affected."), postgreSQL, score(0.6))
	high := e.storeFindingOn(t, "2", vulnerability(t, "CVE-2026-0002", "PostgreSQL is affected."), postgreSQL, score(0.8))
	mid := e.storeFindingOn(t, "1", vulnerability(t, "CVE-2026-0003", "PostgreSQL is affected."), postgreSQL, score(0.7))
	ids := []string{low, high, mid}
	slices.Sort(ids)

	e.prioritizeWith(t, placement(allIn("Todas", ids...)))

	var got []string
	for _, d := range e.deliveries(t) {
		var findings []string
		for _, a := range decode[alert.Batch](t, d.payload).Findings {
			findings = append(findings, a.Finding)
		}
		got = append(got, fmt.Sprintf("%s:%v", d.target, findings))
	}
	want := []string{
		fmt.Sprintf("%s:%v", alert.SecurityTeam, []string{high, mid, low}),
		fmt.Sprintf("%s:%v", owner, []string{mid, low}),
		fmt.Sprintf("ops@example.com:%v", []string{high}),
	}
	if !slices.Equal(got, want) {
		t.Errorf("batches = %v, want %v", got, want)
	}
}

func TestARoundQueuesItsAlertsHighestScoreFirst(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.prioritize(t)
	queued := len(e.deliveries(t))
	lower := e.storeFinding(t, vulnerability(t, "CVE-2026-0001", "PostgreSQL is affected."), postgreSQL, score(0.7))
	higher := e.storeFinding(t, vulnerability(t, "CVE-2026-0002", "PostgreSQL is affected."), postgreSQL, score(0.8))
	placing := []string{lower, higher}
	slices.Sort(placing)

	e.prioritizeWith(t, placement(standing(1), standing(2), allIn("Al final", placing...)))

	var got []string
	for _, d := range e.deliveries(t)[queued:] {
		got = append(got, d.finding.String()+"/"+d.targetKind)
	}
	want := []string{higher + "/email", higher + "/channel", lower + "/email", lower + "/channel"}
	if !slices.Equal(got, want) {
		t.Errorf("deliveries = %v, want %v", got, want)
	}
}

func mustOwner(t *testing.T, email string) inventory.OwnerEmail {
	t.Helper()
	o, err := inventory.NewOwnerEmail(email)
	if err != nil {
		t.Fatal(err)
	}
	return o
}
