package assessment

import (
	"slices"
	"time"
)

// Version is one Prioritization of a Customer's chain as a Finding's history
// reads it (ADR 0036): when it was made, the Business Context version its
// Prioritizer read, and the Finding's Slot in it, nil when it does not hold
// the Finding.
type Version struct {
	Prioritization string
	Created        time.Time
	ContextVersion *int
	Slot           *Slot
}

// Slot is where a Prioritization holds a Finding: the placement it has, when
// that placement was read, the position of its Priority Group from 1, and
// where its Score alone would put it (ADR 0026).
type Slot struct {
	Placement string
	PlacedAt  time.Time
	Group     int
	ScoreRank int
}

// HistoryKind is what an entry of a Finding's history says happened to its
// place (ADR 0036).
type HistoryKind string

const (
	// Placed: the first Prioritization that holds it, or the first after it
	// left.
	Placed HistoryKind = "placed"
	// PlacedAgain: a round placed it again.
	PlacedAgain HistoryKind = "placed_again"
	// Moved: it kept its placement, but its group's position changed.
	Moved HistoryKind = "moved"
	// Left: the Prioritization no longer holds it, because it closed.
	Left HistoryKind = "left"
)

// TimedFeedback is a User's Feedback on where a Finding should be, said
// directly and not through the Analista, with when it was recorded.
type TimedFeedback struct {
	At      time.Time
	Verdict string
	Note    string
}

// HistoryEntry is one change of a Finding's place. Group and rank are 0
// where there is no place: before for Placed, now for Left.
type HistoryEntry struct {
	Prioritization        string
	Created               time.Time
	Kind                  HistoryKind
	GroupBefore, GroupNow int
	RankBefore, RankNow   int
	// Title, Reason and Evidence are the Prioritizer's justification: the
	// title of the Finding's group, the reason of the part that holds it and
	// what that part cites of the Finding. Left has none.
	Title    string
	Reason   string
	Evidence []FindingEvidence
	// Change, Feedback and BusinessContext are why a round placed it again,
	// for PlacedAgain only.
	Change          Change
	Feedback        []TimedFeedback
	BusinessContext bool
	// GroupsAppeared and GroupsGone are, for Moved only, the titles of the
	// groups above it now that were not before, and of those above it before
	// that are not now.
	GroupsAppeared, GroupsGone []string
}

type mark struct {
	index int
	kind  HistoryKind
}

// marks are the versions, oldest first, where the Finding's place changed.
func marks(versions []Version) []mark {
	var out []mark
	for i, v := range versions {
		var before *Slot
		if i > 0 {
			before = versions[i-1].Slot
		}
		now := v.Slot
		switch {
		case before == nil && now != nil:
			out = append(out, mark{i, Placed})
		case before != nil && now == nil:
			out = append(out, mark{i, Left})
		case before == nil:
		case before.Placement != now.Placement:
			out = append(out, mark{i, PlacedAgain})
		case before.Group != now.Group:
			out = append(out, mark{i, Moved})
		}
	}
	return out
}

// HistoryReads is what a Finding's history needs read beyond versions, which
// are oldest first: the Prioritizations whose Priority Groups it reads, and
// the placements whose Dossiers it compares.
func HistoryReads(versions []Version) (prioritizations, placements []string) {
	for _, m := range marks(versions) {
		switch m.kind {
		case Placed:
			prioritizations = append(prioritizations, versions[m.index].Prioritization)
		case PlacedAgain:
			prioritizations = append(prioritizations, versions[m.index].Prioritization)
			placements = append(placements, versions[m.index-1].Slot.Placement, versions[m.index].Slot.Placement)
		case Moved:
			prioritizations = append(prioritizations, versions[m.index-1].Prioritization, versions[m.index].Prioritization)
		}
	}
	return compactStrings(prioritizations), compactStrings(placements)
}

// History is a Finding's history, newest first, from versions, oldest first,
// and what HistoryReads asked for: the Priority Groups of those
// Prioritizations by id, the Dossiers of those placements by id, and the
// Users' direct Feedback on where the Finding should be (ADR 0036).
func History(finding string, versions []Version, lists map[string]PriorityList, dossiers map[string]Dossier, feedback []TimedFeedback) []HistoryEntry {
	ms := marks(versions)
	out := make([]HistoryEntry, 0, len(ms))
	for _, m := range slices.Backward(ms) {
		v := versions[m.index]
		e := HistoryEntry{Prioritization: v.Prioritization, Created: v.Created, Kind: m.kind}
		var before Version
		if m.index > 0 {
			before = versions[m.index-1]
		}
		if before.Slot != nil {
			e.GroupBefore, e.RankBefore = before.Slot.Group, before.Slot.ScoreRank
		}
		if v.Slot != nil {
			e.GroupNow, e.RankNow = v.Slot.Group, v.Slot.ScoreRank
			e.Title, e.Reason, e.Evidence = justification(lists[v.Prioritization], finding, v.Slot.Group)
		}
		switch m.kind {
		case PlacedAgain:
			e.Change = ChangeOf(dossiers[before.Slot.Placement], dossiers[v.Slot.Placement])
			e.Feedback = feedbackBetween(feedback, before.Slot.PlacedAt, v.Slot.PlacedAt)
			e.BusinessContext = !sameVersion(before.ContextVersion, v.ContextVersion)
		case Moved:
			above := titlesAbove(lists[before.Prioritization], before.Slot.Group)
			now := titlesAbove(lists[v.Prioritization], v.Slot.Group)
			e.GroupsAppeared, e.GroupsGone = missing(now, above), missing(above, now)
		}
		out = append(out, e)
	}
	return out
}

// justification is the title of the group at position, from 1, and the
// reason and evidence of its part that holds the Finding.
func justification(l PriorityList, finding string, position int) (string, string, []FindingEvidence) {
	if position < 1 || position > len(l.Groups) {
		return "", "", nil
	}
	g := l.Groups[position-1]
	for _, p := range g.Parts {
		if !slices.Contains(p.Findings, finding) {
			continue
		}
		var evidence []FindingEvidence
		for _, e := range p.Evidence {
			if e.Finding == finding {
				evidence = append(evidence, e)
			}
		}
		return g.Title, p.Reason, evidence
	}
	return g.Title, "", nil
}

// feedbackBetween is the Feedback recorded after since and up to until, when
// a round read the Finding to place it again.
func feedbackBetween(feedback []TimedFeedback, since, until time.Time) []TimedFeedback {
	var out []TimedFeedback
	for _, f := range feedback {
		if f.At.After(since) && !f.At.After(until) {
			out = append(out, f)
		}
	}
	return out
}

func sameVersion(a, b *int) bool {
	return (a == nil) == (b == nil) && (a == nil || *a == *b)
}

// titlesAbove are the titles of the groups before position, from 1.
func titlesAbove(l PriorityList, position int) []string {
	end := min(max(position-1, 0), len(l.Groups))
	out := make([]string, end)
	for i, g := range l.Groups[:end] {
		out[i] = g.Title
	}
	return out
}

// missing are the titles of a that b does not have, in a's order.
func missing(a, b []string) []string {
	var out []string
	for _, t := range a {
		if !slices.Contains(b, t) {
			out = append(out, t)
		}
	}
	return out
}

// compactStrings is ids without repeats, in their first order.
func compactStrings(ids []string) []string {
	var out []string
	for _, id := range ids {
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}
