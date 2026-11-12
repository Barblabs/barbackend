package assessment

import (
	"cmp"
	"encoding/json"
	"math"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	// ScoreShift is how much a Finding's Score must move since it was placed
	// for the Prioritizer to place it again (ADR 0026): a daily EPSS update
	// moves a Score by less, and should not reorder the list every day.
	ScoreShift = 0.1
	// ShownPerGroup is how many Findings of each standing group a round shows
	// the Prioritizer, those of the highest Scores, and MaxShownReason the
	// characters of the reason the group was made with, so a round's request
	// grows with the groups of the order, not with its Findings.
	ShownPerGroup  = 3
	MaxShownReason = 300
)

// knownRansomwareUse is how KEV writes that ransomware campaigns use a
// Vulnerability.
const knownRansomwareUse = "Known"

// Round is what the Prioritizer reads in one request (ADR 0026): the
// Customer's Business Context, the order that stands, the Findings to place
// in it, and what Users said of where some of those should be.
type Round struct {
	// Context is the Customer's Business Context as its business_context/1
	// document, nil when the Customer has stated none.
	Context json.RawMessage
	// Standing is the order the round starts from, empty for a Customer's
	// first round or after its Business Context changed.
	Standing []StandingGroup
	// Briefs are the Findings to place.
	Briefs []Brief
	// Feedback is, by Finding to place, what its Users said since it was last
	// placed about where it should be.
	Feedback map[string][]OrderFeedback
}

// StandingGroup is a Priority Group that keeps its place in a round, by its
// number in the order the round starts from, with its size and its Findings
// of the highest Scores.
type StandingGroup struct {
	Number   int       `json:"number"`
	Title    string    `json:"title"`
	Reason   string    `json:"reason"`
	Size     int       `json:"size"`
	Findings []Summary `json:"findings"`
}

// Summary is what the Prioritizer reads of a Finding that keeps its place:
// enough to tell whether a Finding to place goes before or after it.
type Summary struct {
	Finding          string   `json:"finding"`
	CVE              string   `json:"cve"`
	Asset            string   `json:"asset"`
	Criticality      string   `json:"criticality"`
	Exposure         string   `json:"exposure"`
	CriticalServices []string `json:"critical_services"`
	Component        string   `json:"component"`
	Score            float64  `json:"score"`
	KEV              bool     `json:"kev"`
	EPSS             *float64 `json:"epss"`
	// Exploitation is the ATT&CK ids of the Techniques the Cartógrafo says
	// exploit the Vulnerability.
	Exploitation []string `json:"exploitation"`
}

// Placement is the Prioritizer's answer to a Round: the whole order, the
// first group first. A standing group is named by its number and keeps its
// Findings and its place among the other standing groups; each Finding to
// place either joins one of them or goes in a new group between them.
type Placement struct {
	Groups []PlacedGroup `json:"groups"`
}

// PlacedGroup is one group of a Placement. Standing is the number of a
// standing group, nil for a new one. Findings are the Findings it places: all
// of a new group's, or those that join a standing group. Reason and evidence
// are why those go there; a standing group that gains none needs neither,
// and keeps its title.
type PlacedGroup struct {
	Standing        *int              `json:"standing"`
	Title           string            `json:"title"`
	Findings        []string          `json:"findings"`
	Reason          string            `json:"reason"`
	Evidence        []FindingEvidence `json:"evidence"`
	ContextEvidence []ContextEvidence `json:"context_evidence"`
}

// Order is the order a round starts from: the newest Prioritization's list,
// the Dossier of each of its Findings as it was placed, and those closed
// since. The zero Order is a Customer's first, or one whose Business Context
// changed: every open Finding is placed anew.
type Order struct {
	List   PriorityList
	Placed map[string]Dossier
	Closed map[string]bool
}

// RoundPlan is what the next round places, and the order it places it in.
type RoundPlan struct {
	// Standing is the order that stands, and Placed the Dossiers of its
	// Findings as they were placed.
	Standing PriorityList
	Placed   []Dossier
	// Findings are those to place, at most the limit PlanRound was given.
	Findings []Dossier
}

// PlanRound is the next round of order (ADR 0026), given the Dossiers of the
// Customer's open Findings as they are now and what Users said since each was
// placed about where it should be. It places the open Findings order does not
// hold and those that changed since they were placed, those that changed
// first, then by Score, at most limit; a changed one beyond the limit keeps
// its place until a later round. A closed Finding leaves the order, and one
// whose Dossier could not be built now keeps its place as it was placed.
func PlanRound(order Order, open []Dossier, feedback map[string][]OrderFeedback, limit int) RoundPlan {
	var changed, unplaced []Dossier
	for _, now := range open {
		was, held := order.Placed[now.Finding]
		switch {
		case !held:
			unplaced = append(unplaced, now)
		case Changed(was, now) || len(feedback[now.Finding]) > 0:
			changed = append(changed, now)
		}
	}
	plan := RoundPlan{Findings: firstByScore(limit, changed, unplaced)}
	placing := make(map[string]bool, len(plan.Findings))
	for _, d := range plan.Findings {
		placing[d.Finding] = true
	}
	plan.Standing = order.List.Without(func(id string) bool { return order.Closed[id] || placing[id] })
	for _, g := range plan.Standing.Groups {
		for _, id := range g.Findings() {
			plan.Placed = append(plan.Placed, order.Placed[id])
		}
	}
	return plan
}

// firstByScore is the first limit Findings of each list in turn, each by
// Score, highest first, then by id, so a round is the same on the same
// Findings.
func firstByScore(limit int, lists ...[]Dossier) []Dossier {
	var out []Dossier
	for _, findings := range lists {
		out = append(out, byScore(findings)...)
	}
	return out[:min(len(out), limit)]
}

func byScore(findings []Dossier) []Dossier {
	return slices.SortedStableFunc(slices.Values(findings), func(a, b Dossier) int {
		return cmp.Or(cmp.Compare(b.Score.Value, a.Score.Value), cmp.Compare(a.Finding, b.Finding))
	})
}

// Changed reports whether a Finding placed when its Dossier was was must be
// placed again now that it is now (ADR 0026): because KEV lists it now, or
// says ransomware uses it now, because the Cartógrafo labeled it since,
// or because its Score moved by ScoreShift or more.
func Changed(was, now Dossier) bool {
	switch {
	case was.KEV == nil && now.KEV != nil:
		return true
	case now.KEV != nil && now.KEV.KnownRansomwareCampaignUse == knownRansomwareUse && (was.KEV == nil || was.KEV.KnownRansomwareCampaignUse != knownRansomwareUse):
		return true
	case len(was.Techniques) == 0 && len(now.Techniques) > 0:
		return true
	default:
		return rounded(math.Abs(now.Score.Value-was.Score.Value)) >= ScoreShift
	}
}

// NewStanding is the order a round starts from: the groups of l, numbered
// from 1, each with the reason it was made with, cut to MaxShownReason, and
// its ShownPerGroup Findings of the highest Scores, read from their Dossiers
// among dossiers.
func NewStanding(l PriorityList, dossiers []Dossier) []StandingGroup {
	byID := make(map[string]Dossier, len(dossiers))
	for _, d := range dossiers {
		byID[d.Finding] = d
	}
	out := make([]StandingGroup, len(l.Groups))
	for i, g := range l.Groups {
		ids := g.Findings()
		members := make([]Dossier, len(ids))
		for j, id := range ids {
			members[j] = byID[id]
		}
		shown := firstByScore(ShownPerGroup, members)
		out[i] = StandingGroup{Number: i + 1, Title: g.Title, Size: len(ids), Findings: make([]Summary, len(shown))}
		if len(g.Parts) > 0 {
			out[i].Reason = cut(g.Parts[0].Reason, MaxShownReason)
		}
		for j, d := range shown {
			out[i].Findings[j] = summaryOf(d)
		}
	}
	return out
}

func summaryOf(d Dossier) Summary {
	s := Summary{
		Finding: d.Finding, CVE: d.CVE, Asset: d.Asset.Name, Criticality: d.Asset.Criticality, Exposure: d.Asset.Exposure,
		CriticalServices: []string{}, Component: strings.TrimSpace(d.Component.Name + " " + d.Component.Version),
		Score: d.Score.Value, KEV: d.KEV != nil, Exploitation: []string{},
	}
	for _, c := range d.Asset.CriticalServices {
		s.CriticalServices = append(s.CriticalServices, c.Name)
	}
	if d.EPSS != nil {
		s.EPSS = &d.EPSS.Probability
	}
	for _, t := range d.Techniques {
		if t.Role == RoleExploitation {
			s.Exploitation = append(s.Exploitation, t.AttackID)
		}
	}
	return s
}

// cut is s within limit characters, ending in an ellipsis when it was
// longer.
func cut(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	return string([]rune(s)[:limit-1]) + "…"
}

// Without is l without the Findings drop reports: each part loses them and
// the evidence that cites them, and the parts and groups they leave empty go.
func (l PriorityList) Without(drop func(finding string) bool) PriorityList {
	out := PriorityList{Groups: []PriorityGroup{}}
	for _, g := range l.Groups {
		kept := PriorityGroup{Title: g.Title}
		for _, p := range g.Parts {
			p.Findings = slices.DeleteFunc(slices.Clone(p.Findings), drop)
			if len(p.Findings) == 0 {
				continue
			}
			p.Evidence = slices.DeleteFunc(slices.Clone(p.Evidence), func(e FindingEvidence) bool { return drop(e.Finding) })
			p.ContextEvidence = slices.Clone(p.ContextEvidence)
			kept.Parts = append(kept.Parts, p)
		}
		if len(kept.Parts) > 0 {
			out.Groups = append(out.Groups, kept)
		}
	}
	return out
}

// Merge is the order p gives standing: its groups in p's order, each standing
// one gaining a part for the Findings that join it. It holds only for a p that
// VerifyPlacement found no violation in.
func Merge(standing PriorityList, p Placement) PriorityList {
	out := PriorityList{Groups: make([]PriorityGroup, 0, len(p.Groups))}
	for _, g := range p.Groups {
		part := GroupPart{Findings: slices.Clone(g.Findings), Reason: g.Reason, Evidence: slices.Clone(g.Evidence), ContextEvidence: slices.Clone(g.ContextEvidence)}
		if g.Standing == nil {
			out.Groups = append(out.Groups, PriorityGroup{Title: g.Title, Parts: []GroupPart{part}})
			continue
		}
		kept := standing.Groups[*g.Standing-1]
		merged := PriorityGroup{Title: kept.Title, Parts: slices.Clone(kept.Parts)}
		if len(g.Findings) > 0 {
			merged.Parts = append(merged.Parts, part)
		}
		out.Groups = append(out.Groups, merged)
	}
	return out
}
