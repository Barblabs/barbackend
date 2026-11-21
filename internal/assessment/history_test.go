package assessment_test

import (
	"reflect"
	"testing"
	"time"

	"barbackend/internal/assessment"
)

func titled(title string, parts ...assessment.GroupPart) assessment.PriorityGroup {
	return assessment.PriorityGroup{Title: title, Parts: parts}
}

func orderOf(groups ...assessment.PriorityGroup) assessment.PriorityList {
	return assessment.PriorityList{Groups: groups}
}

func TestHistoryTellsEachChangeOfAFindingsPlaceNewestFirst(t *testing.T) {
	t.Parallel()
	day := func(d int) time.Time { return time.Date(2026, time.November, d, 9, 0, 0, 0, time.UTC) }
	slot := func(placement string, placed, group, rank int) *assessment.Slot {
		return &assessment.Slot{Placement: placement, PlacedAt: day(placed), Group: group, ScoreRank: rank}
	}
	context := 1
	versions := []assessment.Version{
		{Prioritization: "v1", Created: day(1), ContextVersion: &context, Slot: slot("p1", 1, 1, 2)},
		{Prioritization: "v2", Created: day(2), ContextVersion: &context, Slot: slot("p1", 1, 1, 3)},
		{Prioritization: "v3", Created: day(3), ContextVersion: &context, Slot: slot("p1", 1, 2, 3)},
		{Prioritization: "v4", Created: day(4), ContextVersion: &context, Slot: slot("p2", 4, 1, 1)},
		{Prioritization: "v5", Created: day(5), ContextVersion: &context},
		{Prioritization: "v6", Created: day(6), ContextVersion: &context, Slot: slot("p3", 6, 1, 1)},
	}
	expuestos := titled("Expuestos", part("Expuesto a internet.", "f", "g"))
	lists := map[string]assessment.PriorityList{
		"v1": orderOf(expuestos),
		"v2": orderOf(expuestos),
		"v3": orderOf(titled("Ransomware", part("Lo usa ransomware.", "h")), expuestos),
		"v4": orderOf(titled("KEV ahora", part("KEV lo lista.", "f")), titled("Ransomware", part("Lo usa ransomware.", "h"))),
		"v6": orderOf(titled("Reabierto", part("Volvió.", "f"))),
	}
	was, now := dossier(t), dossier(t)
	was.KEV = nil
	dossiers := map[string]assessment.Dossier{"p1": was, "p2": now}
	feedback := []assessment.TimedFeedback{
		{At: day(1).Add(-time.Hour), Verdict: "should_be_later", Note: "before it was placed"},
		{At: day(2), Verdict: "should_be_earlier", Note: "es el de pagos"},
		{At: day(5), Verdict: "should_be_later", Note: "after"},
	}

	prioritizations, placements := assessment.HistoryReads(versions)
	if want := []string{"v1", "v2", "v3", "v4", "v6"}; !reflect.DeepEqual(prioritizations, want) {
		t.Errorf("prioritizations to read = %v, want %v", prioritizations, want)
	}
	if want := []string{"p1", "p2"}; !reflect.DeepEqual(placements, want) {
		t.Errorf("placements to read = %v, want %v", placements, want)
	}

	got := assessment.History("f", versions, lists, dossiers, feedback)

	evidence := []assessment.FindingEvidence{{Finding: "f", Path: "/kev", Value: "null"}}
	score := now.Score.Value
	want := []assessment.HistoryEntry{
		{Prioritization: "v6", Created: day(6), Kind: assessment.Placed, GroupNow: 1, RankNow: 1, Title: "Reabierto", Reason: "Volvió.", Evidence: evidence},
		{Prioritization: "v5", Created: day(5), Kind: assessment.Left, GroupBefore: 1, RankBefore: 1},
		{
			Prioritization: "v4", Created: day(4), Kind: assessment.PlacedAgain, GroupBefore: 2, GroupNow: 1, RankBefore: 3, RankNow: 1,
			Title: "KEV ahora", Reason: "KEV lo lista.", Evidence: evidence,
			Change:   assessment.Change{KEVListed: true, ScoreFrom: score, ScoreTo: score},
			Feedback: []assessment.TimedFeedback{feedback[1]},
		},
		{
			Prioritization: "v3", Created: day(3), Kind: assessment.Moved, GroupBefore: 1, GroupNow: 2, RankBefore: 3, RankNow: 3,
			Title: "Expuestos", Reason: "Expuesto a internet.", Evidence: evidence, GroupsAppeared: []string{"Ransomware"},
		},
		{Prioritization: "v1", Created: day(1), Kind: assessment.Placed, GroupNow: 1, RankNow: 2, Title: "Expuestos", Reason: "Expuesto a internet.", Evidence: evidence},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("history =\n%+v\nwant\n%+v", got, want)
	}
}

func TestHistoryTellsWhyARoundPlacedAFindingAgain(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, time.November, 1, 9, 0, 0, 0, time.UTC)
	one, two := 1, 2
	tests := []struct {
		name            string
		before, after   *int
		businessContext bool
	}{
		{"a newer Business Context", &one, &two, true},
		{"a first Business Context", nil, &one, true},
		{"nothing the rules keep", &one, &one, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			versions := []assessment.Version{
				{Prioritization: "v1", Created: start, ContextVersion: tt.before, Slot: &assessment.Slot{Placement: "p1", PlacedAt: start, Group: 1, ScoreRank: 1}},
				{Prioritization: "v2", Created: start.Add(time.Hour), ContextVersion: tt.after, Slot: &assessment.Slot{Placement: "p2", PlacedAt: start.Add(time.Hour), Group: 1, ScoreRank: 1}},
			}
			d := dossier(t)
			got := assessment.History("f", versions, nil, map[string]assessment.Dossier{"p1": d, "p2": d}, nil)
			if len(got) != 2 || got[0].Kind != assessment.PlacedAgain {
				t.Fatalf("history = %+v, want it placed again", got)
			}
			if got[0].BusinessContext != tt.businessContext || got[0].Change.Any() || len(got[0].Feedback) != 0 {
				t.Errorf("entry = %+v, want only business context %t", got[0], tt.businessContext)
			}
		})
	}
}

func TestHistoryTellsAFindingMovedUpWhenTheGroupAboveItEmptied(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, time.November, 1, 9, 0, 0, 0, time.UTC)
	versions := []assessment.Version{
		{Prioritization: "v1", Created: start, Slot: &assessment.Slot{Placement: "p1", PlacedAt: start, Group: 2, ScoreRank: 2}},
		{Prioritization: "v2", Created: start.Add(time.Hour), Slot: &assessment.Slot{Placement: "p1", PlacedAt: start, Group: 1, ScoreRank: 1}},
	}
	expuestos := titled("Expuestos", part("Expuesto a internet.", "f"))
	lists := map[string]assessment.PriorityList{
		"v1": orderOf(titled("Cerrados después", part("Ya no está.", "h")), expuestos),
		"v2": orderOf(expuestos),
	}

	got := assessment.History("f", versions, lists, nil, nil)

	if len(got) != 2 || got[0].Kind != assessment.Moved || got[0].GroupBefore != 2 || got[0].GroupNow != 1 ||
		!reflect.DeepEqual(got[0].GroupsGone, []string{"Cerrados después"}) || got[0].GroupsAppeared != nil {
		t.Errorf("history = %+v, want it moved up as the group above it emptied", got)
	}
}
