package assessment

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// PriorityList is the order a Prioritization gives a Customer's open
// Findings: Priority Groups, in the order to attend them, each Finding in
// exactly one. It carries no number and changes no Score.
type PriorityList struct {
	Groups []PriorityGroup `json:"groups"`
}

// PriorityGroup is Findings to attend at the same time, with why they go
// there: one Part for the Findings the group was made with, and one for those
// each later round added to it, oldest first (ADR 0026).
type PriorityGroup struct {
	Title string      `json:"title"`
	Parts []GroupPart `json:"parts"`
}

// GroupPart is Findings a round put in a Priority Group, by their ids, with
// the reason and evidence it gave.
type GroupPart struct {
	Findings        []string          `json:"findings"`
	Reason          string            `json:"reason"`
	Evidence        []FindingEvidence `json:"evidence"`
	ContextEvidence []ContextEvidence `json:"context_evidence"`
}

// Findings are the ids of the group's Findings, part by part.
func (g PriorityGroup) Findings() []string {
	var out []string
	for _, p := range g.Parts {
		out = append(out, p.Findings...)
	}
	return out
}

// Reason is the reasons of its parts, oldest first, a blank line apart.
func (g PriorityGroup) Reason() string {
	reasons := make([]string, len(g.Parts))
	for i, p := range g.Parts {
		reasons[i] = p.Reason
	}
	return strings.Join(reasons, "\n\n")
}

// Evidence is what its parts cite of their Findings.
func (g PriorityGroup) Evidence() []FindingEvidence {
	var out []FindingEvidence
	for _, p := range g.Parts {
		out = append(out, p.Evidence...)
	}
	return out
}

// ContextEvidence is what its parts cite of the Business Context.
func (g PriorityGroup) ContextEvidence() []ContextEvidence {
	var out []ContextEvidence
	for _, p := range g.Parts {
		out = append(out, p.ContextEvidence...)
	}
	return out
}

// GroupOf is the position, from 1, of the Priority Group holding the Finding
// of that id, or 0 when none does.
func (l PriorityList) GroupOf(finding string) int {
	for i, g := range l.Groups {
		if slices.Contains(g.Findings(), finding) {
			return i + 1
		}
	}
	return 0
}

// FindingEvidence cites one value of a Finding's Brief: Path is an RFC 6901
// JSON pointer into it, which resolves in its Dossier too, and Value is the
// value as written there, or a quote of at least 20 characters of a longer
// text.
type FindingEvidence struct {
	Finding string `json:"finding"`
	Path    string `json:"path"`
	Value   string `json:"value"`
}

// ContextEvidence cites one value of the Customer's Business Context: Path is
// an RFC 6901 JSON pointer into its business_context/1 document, and Value is
// as FindingEvidence's.
type ContextEvidence struct {
	Path  string `json:"path"`
	Value string `json:"value"`
}

// ActionPlan is Luna's output.
type ActionPlan struct {
	Summary string   `json:"summary"`
	Steps   []string `json:"steps"`
	// FixedVersion is nil when the Dossier does not name one.
	FixedVersion *string `json:"fixed_version"`
	// Mitigation is nil when there is none to offer before patching.
	Mitigation   *string  `json:"mitigation"`
	Verification string   `json:"verification"`
	Sources      []string `json:"sources"`
	// AttackMitigations are MITRE's Mitigations of the Techniques the
	// Dossier holds, those against its exploitation first.
	AttackMitigations []PlanMitigation `json:"attack_mitigations"`
}

// PlanMitigation is one of MITRE's Mitigations of a Technique of the Dossier,
// by their ATT&CK ids, with what to do about it on this Asset.
type PlanMitigation struct {
	Mitigation string `json:"mitigation"`
	Technique  string `json:"technique"`
	Step       string `json:"step"`
}

// Verdict is what a User says about a Finding: whether its Vulnerability
// really affects its Asset, or where the Prioritizer should have put it.
type Verdict int

// Stored as catalog ids (ADR 0006): never renumber.
const (
	VerdictApplies         Verdict = 1
	VerdictDoesNotApply    Verdict = 2
	VerdictRemediated      Verdict = 3
	VerdictShouldBeEarlier Verdict = 4
	VerdictShouldBeLater   Verdict = 5
)

func (v Verdict) String() string {
	switch v {
	case VerdictApplies:
		return "Applies"
	case VerdictDoesNotApply:
		return "Does Not Apply"
	case VerdictRemediated:
		return "Remediated"
	case VerdictShouldBeEarlier:
		return "Should Be Earlier"
	case VerdictShouldBeLater:
		return "Should Be Later"
	default:
		return fmt.Sprintf("Verdict(%d)", int(v))
	}
}

var verdictCodes = map[Verdict]string{
	VerdictApplies:         "applies",
	VerdictDoesNotApply:    "does_not_apply",
	VerdictRemediated:      "remediated",
	VerdictShouldBeEarlier: "should_be_earlier",
	VerdictShouldBeLater:   "should_be_later",
}

// VerdictCodes are the codes clients use, in catalog order.
func VerdictCodes() []string {
	return []string{
		verdictCodes[VerdictApplies], verdictCodes[VerdictDoesNotApply], verdictCodes[VerdictRemediated],
		verdictCodes[VerdictShouldBeEarlier], verdictCodes[VerdictShouldBeLater],
	}
}

// Code is the stable lowercase snake_case name clients use for the verdict.
func (v Verdict) Code() string { return verdictCodes[v] }

// ErrInvalidVerdict is a code that names no Verdict.
var ErrInvalidVerdict = errors.New("invalid verdict")

// ParseVerdict is the inverse of Verdict.Code.
func ParseVerdict(code string) (Verdict, error) {
	for v, c := range verdictCodes {
		if c == code {
			return v, nil
		}
	}
	return 0, fmt.Errorf("%w: %q", ErrInvalidVerdict, code)
}
