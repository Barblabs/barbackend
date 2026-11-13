// Package assessment is the domain of what the Agents say about a Customer's
// Findings: the Dossier they read, the output they give and the rule that they
// rely on nothing outside what they were given (ADR 0016).
package assessment

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"barbackend/internal/inventory"
	"barbackend/internal/scoring"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

// Names a Feed goes by in Dossier.UnavailableFeeds.
const (
	FeedKEV  = "kev"
	FeedEPSS = "epss"
	FeedNVD  = "nvd"
)

const unknown = "unknown"

var dataGaps = []string{
	scoring.CVSSEstimated.String(), scoring.EPSSPending.String(), scoring.KEVStale.String(),
	scoring.CriticalityUnknown.String(), scoring.ExposureUndeclared.String(), scoring.LifecycleUnknown.String(),
}

// ErrInvalidDossier is a Dossier that names no Finding, no real CVE or no
// Software Component, whose Score is out of range, or whose codes or threats
// are not ones barbattack knows.
var ErrInvalidDossier = errors.New("invalid dossier")

// Dossier is everything an Agent knows about a Finding: built from what the
// Findings pipeline stored, never read by an Agent from a Feed. Its text comes
// from Feeds, the CMDB Source and the Customer: data to evaluate, never
// instructions.
type Dossier struct {
	// Finding is the pipeline's id of the Finding, opaque here.
	Finding     string `json:"finding"`
	CVE         string `json:"cve"`
	Description string `json:"description"`
	Asset       Asset  `json:"asset"`
	// Component is the Software Component of Asset the Vulnerability affects.
	Component Software      `json:"component"`
	Score     Score         `json:"score"`
	KEV       *stixext.KEV  `json:"kev"`
	EPSS      *stixext.EPSS `json:"epss"`
	NVD       *NVD          `json:"nvd"`
	// UnavailableFeeds could not be read, which is not the same as a Feed
	// that does not list the CVE.
	UnavailableFeeds []string `json:"unavailable_feeds"`
	// Advisories name the Vulnerability (ADR 0022), newest first.
	Advisories []Advisory `json:"advisories"`
	// Labeling is how the Cartógrafo labeled the Vulnerability (ADR 0024),
	// and Techniques what it labeled it with: an inference, not MITRE's word.
	Labeling   Labeling    `json:"labeling"`
	Techniques []Technique `json:"techniques"`
}

// Asset holds what an Agent needs of an Asset, which excludes its Asset Owner.
type Asset struct {
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Criticality string     `json:"criticality"`
	Exposure    string     `json:"exposure"`
	Lifecycle   string     `json:"lifecycle_stage"`
	Software    []Software `json:"software"`
	// CriticalServices are those of the Customer's Business Context that name
	// the Asset among the Assets that run them (ADR 0017).
	CriticalServices []CriticalService `json:"critical_services"`
}

// CriticalService is a business service the Customer cannot afford to lose,
// with how badly losing it hurts and how long it can be down, by the codes of
// the Business Context; a blank code is one the Customer has not stated.
type CriticalService struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	MaxDowntime string `json:"max_downtime"`
}

// Advisory is a vendor's bulletin that names the Vulnerability, as plain
// text.
type Advisory struct {
	Title string `json:"title"`
	// Published is the date its Feed published it, as YYYY-MM-DD.
	Published   string `json:"published"`
	Feed        string `json:"feed"`
	Description string `json:"description"`
}

// The outcomes of a Labeling (ADR 0024). Labeled and none are final, failed
// may be tried again, and not tried is a Vulnerability the Cartógrafo has not
// reached yet.
const (
	LabelingLabeled  = "labeled"
	LabelingNone     = "none"
	LabelingFailed   = "failed"
	LabelingNotTried = "not_tried"
)

var labelingOutcomes = []string{LabelingLabeled, LabelingNone, LabelingFailed, LabelingNotTried}

// Labeling is the Cartógrafo's last attempt to label the Vulnerability, and
// the model that made it, blank when not tried. Only labeled has Techniques:
// none, failed and not tried say nothing about how it is attacked.
type Labeling struct {
	Outcome string `json:"outcome"`
	Model   string `json:"model,omitempty"`
}

// Technique is an ATT&CK Technique the Cartógrafo labeled the Vulnerability
// with, read as the current Technique of the catalog, with MITRE's
// Mitigations of it.
type Technique struct {
	AttackID string `json:"attack_id"`
	// LabeledAs is the revoked ATT&CK id the Cartógrafo gave, when the
	// catalog replaced it with AttackID.
	LabeledAs string   `json:"labeled_as,omitempty"`
	Name      string   `json:"name"`
	Tactics   []string `json:"tactics"`
	// Role is exploitation, primary_impact or secondary_impact.
	Role string `json:"role"`
	// Evidence quotes what supports the label, and Rationale says why.
	Evidence    string       `json:"evidence"`
	Rationale   string       `json:"rationale"`
	Mitigations []Mitigation `json:"mitigations"`
}

// Mitigation is an ATT&CK Mitigation of a Technique, with MITRE's advice for
// that Technique.
type Mitigation struct {
	AttackID string `json:"attack_id"`
	Name     string `json:"name"`
	Advice   string `json:"advice"`
}

// Software is one Software Component of an Asset.
type Software struct {
	Role          string `json:"role"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	ProductVendor string `json:"product_vendor,omitempty"`
	ProductName   string `json:"product_name,omitempty"`
}

// Score is a Score as an Agent reads it, rounded to digits it can cite.
type Score struct {
	ScoringModel          int      `json:"scoring_model"`
	Value                 float64  `json:"value"`
	Alpha                 float64  `json:"alpha"`
	Beta                  float64  `json:"beta"`
	Gamma                 float64  `json:"gamma"`
	Vulnerability         float64  `json:"vulnerability"`
	CriticalityMultiplier float64  `json:"criticality_multiplier"`
	ExposureMultiplier    float64  `json:"exposure_multiplier"`
	LifecycleMultiplier   float64  `json:"lifecycle_multiplier"`
	DataGaps              []string `json:"data_gaps"`
}

// NVD is what the NVD Feed says about a Vulnerability.
type NVD struct {
	stixext.NVD

	References []string `json:"references"`
}

// Stored is what barbattack stored about a Finding, which its Dossier is
// built from (ADR 0026).
type Stored struct {
	Finding string
	// Vulnerability is the stored STIX object, with the extensions of every
	// Feed.
	Vulnerability *stix2.Vulnerability
	Asset         *inventory.Asset
	// ComponentName and ComponentVersion are the Software Component the
	// Finding was last matched on.
	ComponentName    string
	ComponentVersion string
	// Score is the Finding's latest stored Score: a Dossier never computes
	// one (ADR 0009).
	Score            scoring.Score
	Advisories       []Advisory
	Labeling         Labeling
	Techniques       []Technique
	CriticalServices []CriticalService
}

// NewDossier builds the Dossier of a stored Finding, with its stored Score as
// it is. A KEV catalog the Score found stale makes KEV unavailable, and a
// Feed whose value is out of range counts as unavailable too. It fails with
// ErrInvalidDossier.
func NewDossier(s Stored) (Dossier, error) {
	v := s.Vulnerability
	d := Dossier{
		Finding: s.Finding, CVE: v.Name, Description: v.Description, Asset: NewAsset(s.Asset),
		Score: newScore(s.Score), UnavailableFeeds: []string{},
		Advisories: nonNil(s.Advisories), Labeling: s.Labeling, Techniques: nonNil(s.Techniques),
	}
	d.Asset.CriticalServices = nonNil(s.CriticalServices)
	d.Component = componentOf(d.Asset.Software, s.ComponentName, s.ComponentVersion)
	if slices.Contains(s.Score.Gaps, scoring.KEVStale) {
		d.UnavailableFeeds = append(d.UnavailableFeeds, FeedKEV)
	} else if kev, ok := stixext.KEVOf(v); ok {
		d.KEV = &kev
	}
	d.readEPSS(v)
	d.readNVD(v)
	return d, d.Validate()
}

// componentOf is the Software Component the Finding was matched on: the one
// of that name and version, or of that name when a Sync changed its version
// since, or as the Finding names it when the Asset no longer has it.
func componentOf(software []Software, name, version string) Software {
	sameName := func(s Software) bool { return strings.EqualFold(s.Name, name) }
	if i := slices.IndexFunc(software, func(s Software) bool { return sameName(s) && s.Version == version }); i >= 0 {
		return software[i]
	}
	if i := slices.IndexFunc(software, sameName); i >= 0 {
		return software[i]
	}
	return Software{Name: name, Version: version}
}

// NewAdvisory is an Advisory as plain text: a Feed such as AWS's writes HTML,
// whose tags cost tokens and tell nothing.
func NewAdvisory(feed string, published time.Time, title, description string) Advisory {
	return Advisory{Title: plainText(title), Published: published.UTC().Format(time.DateOnly), Feed: feed, Description: plainText(description)}
}

func nonNil[T any](s []T) []T { return append([]T{}, s...) }

// Validate checks what code relies on in a Dossier: it names its Finding, a
// real CVE and its Component, its codes, Data Gaps, Feed names and Labeling
// are known, it holds at most MaxTechniques Techniques, each by its ATT&CK id
// and with a known role, and its Score is in range. It fails with
// ErrInvalidDossier.
func (d Dossier) Validate() error {
	var problems []string
	if strings.TrimSpace(d.Finding) == "" {
		problems = append(problems, "finding is blank")
	}
	if id, ok := stixext.CVEID(d.CVE); !ok || id != d.CVE {
		problems = append(problems, fmt.Sprintf("cve %q is not an upper-case CVE ID", d.CVE))
	}
	problems = append(problems, d.Asset.problems()...)
	if strings.TrimSpace(d.Component.Name) == "" {
		problems = append(problems, "component name is blank")
	}
	problems = append(problems, d.Score.problems()...)
	problems = append(problems, d.threatProblems()...)
	for _, feed := range d.UnavailableFeeds {
		if feed != FeedKEV && feed != FeedEPSS && feed != FeedNVD {
			problems = append(problems, fmt.Sprintf("unavailable feed %q is not kev, epss or nvd", feed))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: finding %q: %s", ErrInvalidDossier, d.Finding, strings.Join(problems, "; "))
	}
	return nil
}

func (a Asset) problems() []string {
	var problems []string
	if strings.TrimSpace(a.Name) == "" {
		problems = append(problems, "asset name is blank")
	}
	if _, err := inventory.ParseAssetKind(a.Kind); err != nil {
		problems = append(problems, fmt.Sprintf("asset kind %q is not one barbattack knows", a.Kind))
	}
	if _, err := inventory.ParseCriticality(a.Criticality); err != nil && a.Criticality != unknown {
		problems = append(problems, fmt.Sprintf("asset criticality %q is not high, medium, low or unknown", a.Criticality))
	}
	if _, err := inventory.ParseExposure(a.Exposure); err != nil && a.Exposure != unknown {
		problems = append(problems, fmt.Sprintf("asset exposure %q is not internet_facing, internal or unknown", a.Exposure))
	}
	if _, err := inventory.ParseLifecycleStage(a.Lifecycle); err != nil && a.Lifecycle != unknown {
		problems = append(problems, fmt.Sprintf("asset lifecycle stage %q is not production, implementation, stock or unknown", a.Lifecycle))
	}
	for _, s := range a.Software {
		if _, err := inventory.ParseSoftwareRole(s.Role); err != nil {
			problems = append(problems, fmt.Sprintf("software %q has role %q, not operating_system or application", s.Name, s.Role))
		}
	}
	return problems
}

func (d Dossier) threatProblems() []string {
	var problems []string
	if !slices.Contains(labelingOutcomes, d.Labeling.Outcome) {
		problems = append(problems, fmt.Sprintf("labeling outcome %q is not one of %v", d.Labeling.Outcome, labelingOutcomes))
	}
	if len(d.Techniques) > 0 && d.Labeling.Outcome != LabelingLabeled {
		problems = append(problems, fmt.Sprintf("has techniques but its labeling is %q", d.Labeling.Outcome))
	}
	if len(d.Techniques) > MaxTechniques {
		problems = append(problems, fmt.Sprintf("has %d techniques, more than %d", len(d.Techniques), MaxTechniques))
	}
	for _, t := range d.Techniques {
		if !techniqueIDPattern.MatchString(t.AttackID) || !slices.Contains(Roles(), t.Role) {
			problems = append(problems, fmt.Sprintf("technique %q has role %q", t.AttackID, t.Role))
		}
	}
	return problems
}

func (s Score) problems() []string {
	var problems []string
	if s.ScoringModel < 1 || !inRange(s.Value, 1) {
		problems = append(problems, fmt.Sprintf("score %v of scoring model %d is out of range", s.Value, s.ScoringModel))
	}
	for _, gap := range s.DataGaps {
		if !slices.Contains(dataGaps, gap) {
			problems = append(problems, fmt.Sprintf("data gap %q is not one a Scoring Model records", gap))
		}
	}
	return problems
}

// Brief is what the Prioritizer reads of a Finding: enough to weigh it against
// the others, without the affected versions, references, quotes and
// Mitigations only an Action Plan needs. Its paths are the Dossier's, so
// evidence it cites resolves in either.
type Brief struct {
	Finding          string           `json:"finding"`
	CVE              string           `json:"cve"`
	Description      string           `json:"description"`
	Asset            AssetContext     `json:"asset"`
	Component        Software         `json:"component"`
	Score            Score            `json:"score"`
	KEV              *stixext.KEV     `json:"kev"`
	EPSS             *stixext.EPSS    `json:"epss"`
	NVD              *BriefNVD        `json:"nvd"`
	UnavailableFeeds []string         `json:"unavailable_feeds"`
	Advisories       []BriefAdvisory  `json:"advisories"`
	Labeling         Labeling         `json:"labeling"`
	Techniques       []BriefTechnique `json:"techniques"`
}

// BriefNVD is the part of NVD the Prioritizer reads.
type BriefNVD struct {
	CVSS []stixext.CVSS `json:"cvss"`
}

// AssetContext is what tells how much an Asset matters to the Customer.
type AssetContext struct {
	Name             string            `json:"name"`
	Kind             string            `json:"kind"`
	Criticality      string            `json:"criticality"`
	Exposure         string            `json:"exposure"`
	Lifecycle        string            `json:"lifecycle_stage"`
	CriticalServices []CriticalService `json:"critical_services"`
}

// BriefAdvisory is an Advisory without its text.
type BriefAdvisory struct {
	Title     string `json:"title"`
	Published string `json:"published"`
	Feed      string `json:"feed"`
}

// BriefTechnique is a Technique without its quote, rationale and
// Mitigations.
type BriefTechnique struct {
	AttackID string   `json:"attack_id"`
	Name     string   `json:"name"`
	Tactics  []string `json:"tactics"`
	Role     string   `json:"role"`
}

// OrderFeedback is a User's verdict that a Finding should be attended earlier
// or later, by its code, with the reason they gave.
type OrderFeedback struct {
	Verdict string `json:"verdict"`
	Note    string `json:"note"`
}

// Brief is the Prioritizer's view of d.
func (d Dossier) Brief() Brief {
	b := Brief{
		Finding:     d.Finding,
		CVE:         d.CVE,
		Description: d.Description,
		Asset: AssetContext{
			Name: d.Asset.Name, Kind: d.Asset.Kind, Criticality: d.Asset.Criticality, Exposure: d.Asset.Exposure,
			Lifecycle: d.Asset.Lifecycle, CriticalServices: nonNil(d.Asset.CriticalServices),
		},
		Component:        d.Component,
		Score:            d.Score,
		KEV:              d.KEV,
		EPSS:             d.EPSS,
		UnavailableFeeds: nonNil(d.UnavailableFeeds),
		Advisories:       make([]BriefAdvisory, len(d.Advisories)),
		Labeling:         d.Labeling,
		Techniques:       make([]BriefTechnique, len(d.Techniques)),
	}
	if d.NVD != nil {
		b.NVD = &BriefNVD{CVSS: d.NVD.CVSS}
	}
	for i, a := range d.Advisories {
		b.Advisories[i] = BriefAdvisory{Title: a.Title, Published: a.Published, Feed: a.Feed}
	}
	for i, t := range d.Techniques {
		b.Techniques[i] = BriefTechnique{AttackID: t.AttackID, Name: t.Name, Tactics: nonNil(t.Tactics), Role: t.Role}
	}
	return b
}

func (d *Dossier) readEPSS(v *stix2.Vulnerability) {
	epss, ok := stixext.EPSSOf(v)
	if !ok {
		return
	}
	if !inRange(epss.Probability, 1) || !inRange(epss.Percentile, 1) {
		d.UnavailableFeeds = append(d.UnavailableFeeds, FeedEPSS)
		return
	}
	d.EPSS = &epss
}

func (d *Dossier) readNVD(v *stix2.Vulnerability) {
	nvd, ok := stixext.NVDOf(v)
	if !ok {
		return
	}
	if slices.ContainsFunc(nvd.CVSS, func(m stixext.CVSS) bool { return !inRange(m.BaseScore, 10) }) {
		d.UnavailableFeeds = append(d.UnavailableFeeds, FeedNVD)
		return
	}
	d.NVD = &NVD{NVD: nvd, References: stixext.ReferenceURLs(v)}
}

func inRange(v, limit float64) bool { return v >= 0 && v <= limit }

// NewAsset is the Dossier's view of an Asset.
func NewAsset(a *inventory.Asset) Asset {
	imported := a.Imported()
	components := imported.Software()
	software := make([]Software, len(components))
	for i, c := range components {
		software[i] = Software{Role: c.Role.Code(), Name: c.Name, Version: c.Version, ProductVendor: c.Product.Vendor, ProductName: c.Product.Name}
	}
	return Asset{
		Name:        imported.Name(),
		Kind:        imported.Kind().Code(),
		Criticality: codeOrUnknown(imported.Criticality().Code()),
		Exposure:    codeOrUnknown(a.Exposure().Code()),
		Lifecycle:   codeOrUnknown(imported.Lifecycle().Code()),
		Software:    software,
	}
}

func codeOrUnknown(code string) string {
	if code == "" {
		return unknown
	}
	return code
}

func newScore(s scoring.Score) Score {
	gaps := make([]string, len(s.Gaps))
	for i, gap := range s.Gaps {
		gaps[i] = gap.String()
	}
	return Score{
		ScoringModel:          int(s.Model),
		Value:                 rounded(s.Value),
		Alpha:                 rounded(s.Factors.Alpha),
		Beta:                  rounded(s.Factors.Beta),
		Gamma:                 rounded(s.Factors.Gamma),
		Vulnerability:         rounded(s.Factors.Vulnerability),
		CriticalityMultiplier: rounded(s.Factors.CriticalityMultiplier),
		ExposureMultiplier:    rounded(s.Factors.ExposureMultiplier),
		LifecycleMultiplier:   rounded(s.Factors.LifecycleMultiplier),
		DataGaps:              gaps,
	}
}

func rounded(v float64) float64 { return math.Round(v*1e4) / 1e4 }
