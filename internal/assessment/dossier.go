// Package assessment is the domain of what the Agents say about a Customer's
// Findings: the Dossier they read, the output they give and the rule that they
// rely on nothing outside what they were given (ADR 0016).
package assessment

import (
	"cmp"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

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
	scoring.CriticalityUnknown.String(), scoring.ExposureUndeclared.String(),
}

// ErrInvalidDossier is a Dossier that names no Finding, no real CVE or no
// Software Component of its Asset, or whose Score is out of range.
var ErrInvalidDossier = errors.New("invalid dossier")

// Dossier is everything an Agent knows about a Finding: built by the Findings
// pipeline from what it matched, never read by an Agent from a Feed. Its text
// comes from Feeds and the CMDB Source: data to evaluate, never instructions.
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
}

// Asset holds what an Agent needs of an Asset, which excludes its Asset Owner.
type Asset struct {
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Criticality string     `json:"criticality"`
	Exposure    string     `json:"exposure"`
	Software    []Software `json:"software"`
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
	DataGaps              []string `json:"data_gaps"`
}

// NVD is what the NVD Feed says about a Vulnerability.
type NVD struct {
	stixext.NVD

	References []string `json:"references"`
}

// Feeds is what each Feed said about a CVE, nil when it does not list it.
type Feeds struct {
	KEV, EPSS, NVD *stix2.Vulnerability
	// Unavailable names the Feeds that could not be read.
	Unavailable []string
}

// NewDossier builds the Dossier of the Finding that cveID affects component,
// named as one of asset's Software Components, computing its Score with
// Scoring Model 1, as the Findings pipeline does. A missing input becomes a
// Data Gap, and a Feed whose value is out of range counts as unavailable. It
// fails with ErrInvalidDossier.
func NewDossier(finding, cveID string, asset *inventory.Asset, component string, feeds Feeds) (Dossier, error) {
	d := Dossier{Finding: finding, CVE: cveID, Description: description(feeds), Asset: NewAsset(asset), UnavailableFeeds: append([]string{}, feeds.Unavailable...)}
	i := slices.IndexFunc(d.Asset.Software, func(s Software) bool { return strings.EqualFold(s.Name, strings.TrimSpace(component)) })
	if i < 0 {
		return Dossier{}, fmt.Errorf("%w: %q is not a Software Component of %s", ErrInvalidDossier, component, d.Asset.Name)
	}
	d.Component = d.Asset.Software[i]
	in := scoring.Inputs{Criticality: asset.Imported().Criticality(), Exposure: asset.Exposure()}
	if feeds.KEV != nil {
		if kev, ok := stixext.KEVOf(feeds.KEV); ok {
			d.KEV, in.KEVListed = &kev, true
		}
	}
	d.readEPSS(feeds.EPSS, &in)
	d.readNVD(feeds.NVD, &in)
	in.KEVStale = slices.Contains(d.UnavailableFeeds, FeedKEV)
	score, err := scoring.Model1.Compute(in)
	if err != nil {
		return Dossier{}, fmt.Errorf("score %s: %w", cveID, err)
	}
	d.Score = newScore(score)
	return d, d.Validate()
}

// Validate checks what code relies on in a Dossier the pipeline built: it
// names its Finding and a real CVE, its Component is one of its Asset's, its
// codes, Data Gaps and Feed names are known and its Score is in range. It
// fails with ErrInvalidDossier.
func (d Dossier) Validate() error {
	var problems []string
	if strings.TrimSpace(d.Finding) == "" {
		problems = append(problems, "finding is blank")
	}
	if id, ok := stixext.CVEID(d.CVE); !ok || id != d.CVE {
		problems = append(problems, fmt.Sprintf("cve %q is not an upper-case CVE ID", d.CVE))
	}
	problems = append(problems, d.Asset.problems()...)
	if !slices.Contains(d.Asset.Software, d.Component) {
		problems = append(problems, fmt.Sprintf("component %q %q is not one of the asset's software", d.Component.Name, d.Component.Version))
	}
	problems = append(problems, d.Score.problems()...)
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
	for _, s := range a.Software {
		if _, err := inventory.ParseSoftwareRole(s.Role); err != nil {
			problems = append(problems, fmt.Sprintf("software %q has role %q, not operating_system or application", s.Name, s.Role))
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
// the others, without the affected versions and references only an Action
// Plan needs.
type Brief struct {
	Finding          string        `json:"finding"`
	CVE              string        `json:"cve"`
	Description      string        `json:"description"`
	Asset            AssetContext  `json:"asset"`
	Component        Software      `json:"component"`
	Score            Score         `json:"score"`
	KEV              *stixext.KEV  `json:"kev"`
	EPSS             *stixext.EPSS `json:"epss"`
	NVD              *BriefNVD     `json:"nvd"`
	UnavailableFeeds []string      `json:"unavailable_feeds"`
}

// BriefNVD is the part of NVD the Prioritizer reads, at the same path as in
// the Dossier, so evidence it cites resolves in either.
type BriefNVD struct {
	CVSS []stixext.CVSS `json:"cvss"`
}

// AssetContext is what tells how much an Asset matters to the Customer.
type AssetContext struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Criticality string `json:"criticality"`
	Exposure    string `json:"exposure"`
}

// Brief is the Prioritizer's view of d.
func (d Dossier) Brief() Brief {
	b := Brief{
		Finding:          d.Finding,
		CVE:              d.CVE,
		Description:      d.Description,
		Asset:            AssetContext{Name: d.Asset.Name, Kind: d.Asset.Kind, Criticality: d.Asset.Criticality, Exposure: d.Asset.Exposure},
		Component:        d.Component,
		Score:            d.Score,
		KEV:              d.KEV,
		EPSS:             d.EPSS,
		UnavailableFeeds: d.UnavailableFeeds,
	}
	if d.NVD != nil {
		b.NVD = &BriefNVD{CVSS: d.NVD.CVSS}
	}
	if b.UnavailableFeeds == nil {
		b.UnavailableFeeds = []string{}
	}
	return b
}

func (d *Dossier) readEPSS(v *stix2.Vulnerability, in *scoring.Inputs) {
	if v == nil {
		return
	}
	epss, ok := stixext.EPSSOf(v)
	if !ok {
		return
	}
	if !inRange(epss.Probability, 1) || !inRange(epss.Percentile, 1) {
		d.UnavailableFeeds = append(d.UnavailableFeeds, FeedEPSS)
		return
	}
	d.EPSS, in.EPSS = &epss, &epss.Probability
}

func (d *Dossier) readNVD(v *stix2.Vulnerability, in *scoring.Inputs) {
	if v == nil {
		return
	}
	nvd, ok := stixext.NVDOf(v)
	if !ok {
		return
	}
	base := baseScore(nvd.CVSS)
	if base != nil && !inRange(*base, 10) {
		d.UnavailableFeeds = append(d.UnavailableFeeds, FeedNVD)
		return
	}
	d.NVD, in.CVSS = &NVD{NVD: nvd, References: stixext.ReferenceURLs(v)}, base
}

func inRange(v, limit float64) bool { return v >= 0 && v <= limit }

// Listed is whether any Feed said something about the CVE.
func (f Feeds) Listed() bool { return f.KEV != nil || f.EPSS != nil || f.NVD != nil }

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
		Software:    software,
	}
}

func codeOrUnknown(code string) string {
	if code == "" {
		return unknown
	}
	return code
}

func description(feeds Feeds) string {
	for _, v := range []*stix2.Vulnerability{feeds.NVD, feeds.KEV} {
		if v != nil && v.Description != "" {
			return v.Description
		}
	}
	return ""
}

func baseScore(metrics []stixext.CVSS) *float64 {
	for _, kind := range []string{"Primary", "Secondary"} {
		matching := slices.DeleteFunc(slices.Clone(metrics), func(m stixext.CVSS) bool { return m.Type != kind })
		if len(matching) == 0 {
			continue
		}
		newest := slices.MaxFunc(matching, func(a, b stixext.CVSS) int { return cmp.Compare(a.Version, b.Version) })
		return &newest.BaseScore
	}
	return nil
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
		DataGaps:              gaps,
	}
}

func rounded(v float64) float64 { return math.Round(v*1e4) / 1e4 }
