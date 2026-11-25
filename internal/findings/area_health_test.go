package findings_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"barbackend/internal/finding"
	"barbackend/internal/findings"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

// inArea puts the records' Assets in a new Active Area named name, and returns
// its id.
func (w world) inArea(t *testing.T, name string, records ...string) int64 {
	t.Helper()
	var id int64
	if err := w.conn.QueryRow(context.Background(), `
		INSERT INTO customer_areas (cmdb_source_id, record_id, name) VALUES ($1, $2, $2) RETURNING id`,
		uuid.UUID(w.source), name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		w.exec(t, `UPDATE assets SET area_record_id = $1 WHERE record_id = $2`, name, r)
	}
	return id
}

type timedScore struct {
	model int
	value float64
	at    time.Time
}

// scoreHistory makes scores the only Scores of the record's only Finding.
func (w world) scoreHistory(t *testing.T, record string, scores ...timedScore) {
	t.Helper()
	w.exec(t, `DELETE FROM finding_score_data_gaps WHERE finding_id = (SELECT id FROM findings WHERE record_id = $1)`, record)
	w.exec(t, `DELETE FROM finding_scores WHERE finding_id = (SELECT id FROM findings WHERE record_id = $1)`, record)
	for _, s := range scores {
		w.exec(t, `
			INSERT INTO finding_scores (finding_id, scored_at, model, value, alpha, beta, gamma, vulnerability,
			                            criticality_multiplier, exposure_multiplier, lifecycle_multiplier)
			SELECT id, $2, $3, $4, 0.5, 0.5, 0.5, 0.5, 1, 1, 1 FROM findings WHERE record_id = $1`,
			record, s.at, s.model, s.value)
	}
}

func critical(at time.Time) timedScore { return timedScore{model: 3, value: 0.9, at: at} }
func high(at time.Time) timedScore     { return timedScore{model: 3, value: 0.5, at: at} }

func (w world) areaHealth(t *testing.T, caller tenancy.User) []findings.AreaHealth {
	t.Helper()
	got, err := w.findings.AreaHealth(context.Background(), caller)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

type flag struct {
	name    string
	reasons []findings.HealthReason
}

func flags(health []findings.AreaHealth) []flag {
	out := make([]flag, len(health))
	for i, h := range health {
		out[i] = flag{h.Name, h.Reasons}
	}
	return out
}

func TestAreaHealthFlagsAnAgingCriticalAndAGrowingBacklogButNotALargeShrinkingOne(t *testing.T) {
	t.Parallel()
	growing := []string{"g1", "g2", "g3"}
	large := []string{"l1", "l2", "l3", "l4", "l5", "l6", "l7", "l8", "l9"}
	w := nginxWorld(t, append(append([]string{"aging"}, growing...), large...)...)
	w.inArea(t, "Payments", "aging")
	w.inArea(t, "Billing", growing...)
	w.inArea(t, "Accounting", large...)
	w.scoreHistory(t, "aging", critical(closesNow.AddDate(0, 0, -31)))
	for i, r := range growing {
		w.setHistory(t, r, closesNow.AddDate(0, 0, -8-7*i), time.Time{})
	}
	for i, r := range large[6:] {
		w.closeAs(t, r, finding.Remediated, openedLongAgo, closesNow.AddDate(0, 0, -8-7*i))
	}
	for _, r := range append(growing[2:], large...) {
		w.scoreHistory(t, r, high(openedLongAgo))
	}
	for _, r := range growing[:2] {
		w.scoreHistory(t, r, critical(closesNow.AddDate(0, 0, -1)))
	}

	got := flags(w.areaHealth(t, w.viewer(t)))

	want := []flag{
		{"Payments", []findings.HealthReason{findings.AgingCritical}},
		{"Billing", []findings.HealthReason{findings.Growing}},
		{"Accounting", []findings.HealthReason{}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("areas = %v, want %v", got, want)
	}
}

func TestAreaHealthCountsTheOldestCriticalFromWhenItsLatestRunOfCriticalScoresBegan(t *testing.T) {
	t.Parallel()
	w := nginxWorld(t, "a")
	w.inArea(t, "IT", "a")
	w.scoreHistory(t, "a",
		high(closesNow.AddDate(0, 0, -60)),
		critical(closesNow.AddDate(0, 0, -50)),
		timedScore{model: 2, value: 0.9, at: closesNow.AddDate(0, 0, -20)},
		critical(closesNow.AddDate(0, 0, -10)),
		critical(closesNow.AddDate(0, 0, -5)),
	)

	got := w.areaHealth(t, w.viewer(t))

	if len(got) != 1 || got[0].OldestCriticalDays == nil || *got[0].OldestCriticalDays != 10 || got[0].NeedsHelp() {
		t.Fatalf("areas = %+v, want IT Critical for 10 days and not flagged", got)
	}
}

func TestAreaHealthCountsFixedClosesAndTheBacklogOf30DaysAgo(t *testing.T) {
	t.Parallel()
	w := nginxWorld(t, "open-before", "open-since", "fixed", "went-away", "fixed-long-ago")
	w.inArea(t, "IT", "open-before", "open-since", "fixed", "went-away", "fixed-long-ago")
	w.setHistory(t, "open-since", closesNow.AddDate(0, 0, -10), time.Time{})
	w.closeAs(t, "fixed", finding.Remediated, openedLongAgo, closesNow.AddDate(0, 0, -10))
	w.closeAs(t, "went-away", finding.AssetInactive, openedLongAgo, closesNow.AddDate(0, 0, -10))
	w.closeAs(t, "fixed-long-ago", finding.Remediated, openedLongAgo, closesNow.AddDate(0, 0, -35))

	got := w.areaHealth(t, w.viewer(t))

	if len(got) != 1 || got[0].Fixed != 1 || got[0].Open30DaysAgo != 3 {
		t.Fatalf("areas = %+v, want IT with 1 fixed and 3 open 30 days ago", got)
	}
}

func TestAreaHealthAddsUpToTheSummaryWithAnEntryForAssetsWithoutArea(t *testing.T) {
	t.Parallel()
	w := nginxWorld(t, "in-area", "no-area-1", "no-area-2", "unscored")
	w.inArea(t, "IT", "in-area")
	w.scoreHistory(t, "in-area", critical(closesNow.AddDate(0, 0, -1)))
	w.scoreHistory(t, "no-area-1", critical(closesNow.AddDate(0, 0, -1)))
	w.scoreHistory(t, "no-area-2", high(closesNow.AddDate(0, 0, -1)))
	w.scoreHistory(t, "unscored")

	got := w.areaHealth(t, w.viewer(t))
	sum, err := w.findings.Summary(context.Background(), w.viewer(t))
	if err != nil {
		t.Fatal(err)
	}

	var open, crit int
	for _, a := range got {
		open += a.Open.Total()
		crit += a.Open.Critical
	}
	if len(got) != 2 || got[0].AssetCount != 1 || got[1].ID != nil || got[1].AssetCount != 3 ||
		got[1].Open.Critical != 1 || got[1].Open.High != 1 || got[1].Open.Total() != 2 {
		t.Fatalf("areas = %+v, want IT with 1 Asset, then no Area with 3 Assets and 1 Critical and 1 High open", got)
	}
	if open != sum.Bands.Total() || crit != sum.Bands.Critical {
		t.Errorf("areas add up to %d open and %d Critical, summary has %d and %d", open, crit, sum.Bands.Total(), sum.Bands.Critical)
	}
}

func TestAreaHealthSortsByOldestCriticalThenMostCriticalThenNameWithNoAreaLast(t *testing.T) {
	t.Parallel()
	w := nginxWorld(t, "beta", "zeta-1", "zeta-2", "eta", "delta", "alpha", "none")
	w.inArea(t, "Beta", "beta")
	w.inArea(t, "Zeta", "zeta-1", "zeta-2")
	w.inArea(t, "Eta", "eta")
	w.inArea(t, "Delta", "delta")
	w.inArea(t, "Alpha", "alpha")
	w.scoreHistory(t, "beta", critical(closesNow.AddDate(0, 0, -10)))
	for _, r := range []string{"zeta-1", "zeta-2", "eta"} {
		w.scoreHistory(t, r, critical(closesNow.AddDate(0, 0, -5)))
	}
	for _, r := range []string{"delta", "alpha", "none"} {
		w.scoreHistory(t, r, high(openedLongAgo))
	}

	var got []string
	for _, a := range w.areaHealth(t, w.viewer(t)) {
		got = append(got, a.Name)
	}

	if want := []string{"Beta", "Zeta", "Eta", "Alpha", "Delta", ""}; !reflect.DeepEqual(got, want) {
		t.Errorf("order = %q, want %q", got, want)
	}
}

func TestAreaHealthLeavesOutInactiveAreasAndAnotherCustomersAreas(t *testing.T) {
	t.Parallel()
	w := nginxWorld(t, "a", "b")
	w.inArea(t, "Active", "a")
	w.inArea(t, "Closed down", "b")
	w.exec(t, `UPDATE customer_areas SET inactive_since = now() WHERE name = 'Closed down'`)
	other := w
	other.customer = tenancy.CustomerID(uuid.New())
	w.exec(t, `INSERT INTO customers (id, name) VALUES ($1, 'other')`, uuid.UUID(other.customer))

	if got := flags(w.areaHealth(t, w.viewer(t))); len(got) != 1 || got[0].name != "Active" {
		t.Errorf("areas = %v, want only Active", got)
	}
	if got := w.areaHealth(t, other.viewer(t)); len(got) != 0 {
		t.Errorf("another Customer's areas = %+v, want none", got)
	}
}
