// Package alert is what an Alert says about a Finding (ADR 0033): the
// payload the Prioritizer writes into a Slack delivery and the slack worker
// renders, which reads nothing else.
package alert

import (
	"cmp"
	"slices"
)

const (
	// KindFinding is a delivery about one Finding, and KindBatch one about up
	// to BatchSize, sent during a Customer's Initial Load.
	KindFinding = "finding"
	KindBatch   = "finding_batch"
	BatchSize   = 10
	// SecurityTeam is the target of a channel delivery: the worker sends it
	// to the channel the Customer's installation names when it sends, so a
	// delivery written before a channel was picked, or one changed since,
	// goes where the Security Team reads now.
	SecurityTeam = "security-team"
	// TargetEmail is a delivery to an Asset Owner, by email, and
	// TargetChannel one to the Security Team channel (ADR 0030).
	TargetEmail   = "email"
	TargetChannel = "channel"
)

// Reason is why a Finding is alerted.
type Reason string

const (
	// New is a Finding the previous Prioritization does not hold.
	New Reason = "new"
	// BandRose is a Finding whose Score Band is higher than the one it was
	// placed with.
	BandRose Reason = "band_rose"
)

// Finding is an Alert about one Finding, as it was placed: what the message
// shows, and why the Prioritizer placed it where it did.
type Finding struct {
	Finding        string  `json:"finding_id"`
	Prioritization string  `json:"prioritization_id"`
	Reason         Reason  `json:"reason"`
	BandWas        string  `json:"band_was,omitempty"`
	CVE            string  `json:"cve"`
	Asset          string  `json:"asset"`
	Component      string  `json:"component"`
	OwnerEmail     string  `json:"owner_email"`
	PortalURL      string  `json:"portal_url"`
	Score          float64 `json:"score"`
	Band           string  `json:"score_band"`
	// CVSS is nil when NVD reports none, and EPSS when the Feed has not
	// scored the CVE yet.
	CVSS           *float64 `json:"cvss"`
	EPSS           *float64 `json:"epss"`
	KEV            bool     `json:"kev"`
	Criticality    string   `json:"criticality"`
	Exposure       string   `json:"exposure"`
	Lifecycle      string   `json:"lifecycle_stage"`
	Classification string   `json:"information_classification"`
	Group          Group    `json:"group"`
}

// Group is the Priority Group the Prioritizer placed a Finding in: its
// position from 1, of how many, its title, and the Prioritizer's reason for
// the Findings it put there with it.
type Group struct {
	Position int    `json:"position"`
	Of       int    `json:"of"`
	Title    string `json:"title"`
	Reason   string `json:"reason"`
}

// Batch is an Alert about up to BatchSize Findings for the same target.
type Batch struct {
	Findings []Finding `json:"findings"`
}

// ByScore orders Alerts highest Score first, then by Finding, so the same
// Alerts are always sent in the same order.
func ByScore(a, b Finding) int {
	return cmp.Or(cmp.Compare(b.Score, a.Score), cmp.Compare(a.Finding, b.Finding))
}

// Batches is findings in batches of BatchSize, in ByScore order.
func Batches(findings []Finding) []Batch {
	sorted := slices.SortedFunc(slices.Values(findings), ByScore)
	var out []Batch
	for chunk := range slices.Chunk(sorted, BatchSize) {
		out = append(out, Batch{Findings: chunk})
	}
	return out
}
