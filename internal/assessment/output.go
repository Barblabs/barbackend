package assessment

import (
	"errors"
	"fmt"
)

// PriorityList is the Prioritizer's output: every Finding it was given, in
// Priority Groups, in the order to attend them. It carries no number and
// changes no Score.
type PriorityList struct {
	Groups []PriorityGroup `json:"groups"`
}

// PriorityGroup is Findings to attend at the same time, by their ids.
type PriorityGroup struct {
	Title    string            `json:"title"`
	Findings []string          `json:"findings"`
	Reason   string            `json:"reason"`
	Evidence []FindingEvidence `json:"evidence"`
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
