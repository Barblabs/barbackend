package assessment_test

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"barbackend/internal/assessment"
	"barbackend/internal/stixext"
)

func part(reason string, findings ...string) assessment.GroupPart {
	evidence := make([]assessment.FindingEvidence, len(findings))
	for i, id := range findings {
		evidence[i] = assessment.FindingEvidence{Finding: id, Path: "/kev", Value: "null"}
	}
	return assessment.GroupPart{Findings: findings, Reason: reason, Evidence: evidence}
}

// list is an order of three groups: f-0 alone, then f-1 with f-2, which a
// later round added, then f-3.
func list() assessment.PriorityList {
	return assessment.PriorityList{Groups: []assessment.PriorityGroup{
		{Title: "Primero", Parts: []assessment.GroupPart{part("Va primero.", "f-0")}},
		{Title: "Juntos", Parts: []assessment.GroupPart{part("Una actualización.", finding), part("Se suma.", osFind)}},
		{Title: "Al final", Parts: []assessment.GroupPart{part("Va al final.", "f-3")}},
	}}
}

func TestAGroupReadsAsItsParts(t *testing.T) {
	t.Parallel()
	g := list().Groups[1]
	if !slices.Equal(g.Findings(), []string{finding, osFind}) || g.Reason() != "Una actualización.\n\nSe suma." || len(g.Evidence()) != 2 {
		t.Errorf("group = %v, %q, %v", g.Findings(), g.Reason(), g.Evidence())
	}
	if l := list(); l.GroupOf(osFind) != 2 || l.GroupOf("f-9") != 0 {
		t.Errorf("groups = %d, %d", l.GroupOf(osFind), l.GroupOf("f-9"))
	}
}

func TestNewStandingShowsEachGroupInBrief(t *testing.T) {
	t.Parallel()
	l := list()
	for i := range 5 {
		l.Groups[2].Parts[0].Findings = append(l.Groups[2].Parts[0].Findings, "f-x"+string(rune('a'+i)))
	}
	l.Groups[2].Parts[0].Reason = strings.Repeat("larga ", 100)
	dossiers := []assessment.Dossier{standingDossier(t, "f-0"), dossier(t), osDossier(t)}
	for i, id := range l.Groups[2].Findings() {
		d := standingDossier(t, id)
		d.Score.Value = float64(i) / 10
		dossiers = append(dossiers, d)
	}

	standing := assessment.NewStanding(l, dossiers)

	if len(standing) != 3 || standing[1].Number != 2 || standing[1].Title != "Juntos" || standing[1].Reason != "Una actualización." || standing[1].Size != 2 {
		t.Fatalf("standing = %+v", standing)
	}
	want := assessment.Summary{
		Finding: finding, CVE: cve, Asset: "pg-prod-01", Criticality: "high", Exposure: "unknown",
		Lifecycle: "production", CriticalServices: []string{"Pagos en línea"}, Component: "PostgreSQL 15.6",
		Score: 0.9131, KEV: true, EPSS: ptr(0.9003), Exploitation: []string{"T1190"},
	}
	if !reflect.DeepEqual(standing[1].Findings[0], want) {
		t.Errorf("summary = %+v, want %+v", standing[1].Findings[0], want)
	}
	last := standing[2]
	if last.Size != 6 || len(last.Findings) != assessment.ShownPerGroup || last.Findings[0].Finding != "f-xe" || utf8.RuneCountInString(last.Reason) != assessment.MaxShownReason {
		t.Errorf("a large group = size %d, shown %+v, reason of %d characters, want its highest Scores and a cut reason", last.Size, last.Findings, utf8.RuneCountInString(last.Reason))
	}
}

func TestWithoutDropsFindingsTheirEvidenceAndEmptyPartsAndGroups(t *testing.T) {
	t.Parallel()
	got := list().Without(func(id string) bool { return id == "f-0" || id == osFind })

	want := assessment.PriorityList{Groups: []assessment.PriorityGroup{
		{Title: "Juntos", Parts: []assessment.GroupPart{part("Una actualización.", finding)}},
		{Title: "Al final", Parts: []assessment.GroupPart{part("Va al final.", "f-3")}},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("without = %+v, want %+v", got, want)
	}
	if len(list().Groups[1].Findings()) != 2 {
		t.Error("Without changed the list it was called on")
	}
}

func TestMergeKeepsStandingGroupsAndAddsAPartForWhatJoinsThem(t *testing.T) {
	t.Parallel()
	standing := assessment.PriorityList{Groups: []assessment.PriorityGroup{
		{Title: "Primero", Parts: []assessment.GroupPart{part("Va primero.", "f-0")}},
		{Title: "Al final", Parts: []assessment.GroupPart{part("Va al final.", "f-3")}},
	}}
	joining := assessment.FindingEvidence{Finding: osFind, Path: "/kev", Value: "null"}
	p := assessment.Placement{Groups: []assessment.PlacedGroup{
		{Title: "Nuevo y urgente", Findings: []string{finding}, Reason: "En KEV.", Evidence: []assessment.FindingEvidence{{Finding: finding, Path: "/kev/date_added", Value: "2025-09-29"}}},
		{Standing: ptr(1)},
		{Standing: ptr(2), Findings: []string{osFind}, Reason: "Igual de tardío.", Evidence: []assessment.FindingEvidence{joining}},
	}}

	got := assessment.Merge(standing, p)

	if len(got.Groups) != 3 || got.Groups[0].Title != "Nuevo y urgente" || !reflect.DeepEqual(got.Groups[1], standing.Groups[0]) {
		t.Fatalf("merged = %+v", got)
	}
	last := got.Groups[2]
	if last.Title != "Al final" || len(last.Parts) != 2 || !slices.Equal(last.Findings(), []string{"f-3", osFind}) || last.Parts[1].Reason != "Igual de tardío." || !slices.Equal(last.Parts[1].Evidence, []assessment.FindingEvidence{joining}) {
		t.Errorf("standing group that gained one = %+v", last)
	}
	if len(standing.Groups[1].Parts) != 1 {
		t.Error("Merge changed the standing list")
	}
}

func TestPlanRoundPlacesWhatIsNewOrChangedAndKeepsTheRest(t *testing.T) {
	t.Parallel()
	moved := dossier(t)
	moved.Score.Value = 0.5
	gone, broken, kept := standingDossier(t, "f-0"), standingDossier(t, "f-3"), osDossier(t)
	newer, older := standingDossier(t, "f-8"), standingDossier(t, "f-9")
	newer.Score.Value, older.Score.Value = 0.7, 0.2
	order := assessment.Order{
		List:   list(),
		Placed: map[string]assessment.Dossier{"f-0": gone, finding: dossier(t), osFind: kept, "f-3": broken},
		Closed: map[string]bool{"f-0": true},
	}

	plan := assessment.PlanRound(order, []assessment.Dossier{moved, kept, older, newer}, nil, 3)

	if ids := idsOf(plan.Findings); !slices.Equal(ids, []string{finding, "f-8", "f-9"}) {
		t.Errorf("placed = %v, want the changed one first, then the new ones by Score", ids)
	}
	if !slices.Equal(plan.Standing.Groups[0].Findings(), []string{osFind}) || !slices.Equal(plan.Standing.Groups[1].Findings(), []string{"f-3"}) || len(plan.Standing.Groups) != 2 {
		t.Errorf("standing = %+v, want the closed one out and the one whose Dossier could not be built kept", plan.Standing)
	}
	if ids := idsOf(plan.Placed); !slices.Equal(ids, []string{osFind, "f-3"}) {
		t.Errorf("standing dossiers = %v", ids)
	}

	limited := assessment.PlanRound(order, []assessment.Dossier{moved, kept, older, newer}, nil, 1)
	if ids := idsOf(limited.Findings); !slices.Equal(ids, []string{finding}) || limited.Standing.GroupOf("f-8") != 0 {
		t.Errorf("placed within a limit of 1 = %v", ids)
	}
	asked := assessment.PlanRound(order, []assessment.Dossier{dossier(t), kept}, map[string][]assessment.OrderFeedback{osFind: {{Verdict: "should_be_later"}}}, 3)
	if ids := idsOf(asked.Findings); !slices.Equal(ids, []string{osFind}) {
		t.Errorf("placed with feedback = %v, want the Finding a User spoke of", ids)
	}
	anew := assessment.PlanRound(assessment.Order{}, []assessment.Dossier{kept, dossier(t)}, nil, 3)
	if ids := idsOf(anew.Findings); !slices.Equal(ids, []string{finding, osFind}) || len(anew.Standing.Groups) != 0 {
		t.Errorf("a first round placed %v, want every open Finding by Score", ids)
	}
}

func idsOf(dossiers []assessment.Dossier) []string {
	ids := make([]string, len(dossiers))
	for i, d := range dossiers {
		ids[i] = d.Finding
	}
	return ids
}

func TestChanged(t *testing.T) {
	t.Parallel()
	ransomware := func(use string) *stixext.KEV {
		return &stixext.KEV{DateAdded: "2025-09-29", KnownRansomwareCampaignUse: use}
	}
	tests := []struct {
		name   string
		change func(was, now *assessment.Dossier)
		want   bool
	}{
		{"nothing", func(_, _ *assessment.Dossier) {}, false},
		{"a small move of its Score", func(_, now *assessment.Dossier) { now.Score.Value += assessment.ScoreShift / 2 }, false},
		{"its Score moved up", func(_, now *assessment.Dossier) { now.Score.Value += assessment.ScoreShift }, true},
		{"its Score moved down", func(_, now *assessment.Dossier) { now.Score.Value -= assessment.ScoreShift }, true},
		{"KEV lists it now", func(was, _ *assessment.Dossier) { was.KEV = nil }, true},
		{"KEV no longer lists it", func(_, now *assessment.Dossier) { now.KEV = nil }, false},
		{"ransomware uses it now", func(was, now *assessment.Dossier) { was.KEV, now.KEV = ransomware("Unknown"), ransomware("Known") }, true},
		{"ransomware used it already", func(was, now *assessment.Dossier) { was.KEV, now.KEV = ransomware("Known"), ransomware("Known") }, false},
		{"the Cartógrafo labeled it since", func(was, _ *assessment.Dossier) { was.Techniques = nil }, true},
		{"the Cartógrafo labeled it already", func(_, now *assessment.Dossier) { now.Techniques = append(now.Techniques, now.Techniques[0]) }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			was, now := dossier(t), dossier(t)
			tt.change(&was, &now)
			if got := assessment.Changed(was, now); got != tt.want {
				t.Errorf("Changed = %v, want %v", got, tt.want)
			}
		})
	}
}
