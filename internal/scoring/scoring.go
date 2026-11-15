// Package scoring computes the Score of a Finding with a versioned Scoring Model (ADR 0009).
package scoring

import (
	"errors"
	"fmt"
	"math"

	"barbackend/internal/inventory"
)

var (
	ErrInvalidCVSS = errors.New("cvss base score out of range")
	ErrInvalidEPSS = errors.New("epss probability out of range")
)

// Inputs are everything a Score depends on. A nil CVSS or EPSS means the
// Feed has no value yet, which is not the same as a value of 0.
type Inputs struct {
	CVSS        *float64 // base score, 0–10
	EPSS        *float64 // probability, 0–1, not the percentile
	KEVListed   bool     // listed in the last KEV catalog read
	KEVStale    bool     // that catalog is older than expected, or was never read
	Criticality inventory.Criticality
	Exposure    inventory.Exposure
	Lifecycle   inventory.LifecycleStage
	// Classification is read only by a Model that scores it (ADR 0032).
	Classification inventory.InformationClassification
}

type DataGap int

// Stored as catalog ids (ADR 0006): never renumber.
const (
	CVSSEstimated      DataGap = 1
	EPSSPending        DataGap = 2
	KEVStale           DataGap = 3
	CriticalityUnknown DataGap = 4
	ExposureUndeclared DataGap = 5
	LifecycleUnknown   DataGap = 6
	// ClassificationUndeclared is recorded only by a Model that scores the
	// Information Classification (ADR 0032).
	ClassificationUndeclared DataGap = 7
)

func (g DataGap) String() string {
	switch g {
	case CVSSEstimated:
		return "cvss_estimated"
	case EPSSPending:
		return "epss_pending"
	case KEVStale:
		return "kev_stale"
	case CriticalityUnknown:
		return "criticality_unknown"
	case ExposureUndeclared:
		return "exposure_undeclared"
	case LifecycleUnknown:
		return "lifecycle_unknown"
	case ClassificationUndeclared:
		return "information_classification_undeclared"
	default:
		return fmt.Sprintf("DataGap(%d)", int(g))
	}
}

type ModelVersion int

// Model is a Scoring Model. Its fields are unexported so a published version
// can never be edited: changing any number means a new Model.
type Model struct {
	version                  ModelVersion
	wCVSS, wEPSS, wKEV       float64
	critHigh, critMedium     float64
	critLow, critUnknown     float64
	expInternet, expInternal float64
	expUnknown               float64
	// scoresLifecycle is false for a Model that had no lifecycle factor: its
	// multiplier is 1 and the Lifecycle Stage is not read.
	scoresLifecycle         bool
	lifeProduction, lifeImp float64
	lifeStock, lifeUnknown  float64
	defaultCVSS             float64
	// weighsByExploitSignal replaces the weighted sum of layer 1 with the
	// severity weighed by ExploitSignal (ADR 0032); the w* weights are unused.
	weighsByExploitSignal bool
	epssSaturation        float64 // the EPSS that counts as an ExploitSignal of 1
	unexploitedShare      float64 // the share of the severity at an ExploitSignal of 0
	// scoresClassification makes the impact the higher of Criticality and the
	// Information Classification; Unclassified does not count (ADR 0032).
	scoresClassification                      bool
	classConfidential, classPrivate, classPub float64
	bands                                     []bandFloor // highest first; none before Model 3
}

// bandFloor is the lowest Score of a Band.
type bandFloor struct {
	band  Band
	floor float64
}

// Model1 is the linear model of ADR 0009. Unknown Criticality and Exposure
// take the highest multiplier, so missing context never lowers a Score.
var Model1 = Model{
	version: 1,
	wCVSS:   0.3, wEPSS: 0.3, wKEV: 0.4,
	critHigh: 1.0, critMedium: 0.7, critLow: 0.4, critUnknown: 1.0,
	expInternet: 1.0, expInternal: 0.6, expUnknown: 1.0,
	defaultCVSS: 0.7,
}

// Model2 is Model1 with the Lifecycle Stage as a third Asset multiplier
// (ADR 0028). An Unknown stage takes the highest one, as in Model1.
var Model2 = Model{
	version: 2,
	wCVSS:   0.3, wEPSS: 0.3, wKEV: 0.4,
	critHigh: 1.0, critMedium: 0.7, critLow: 0.4, critUnknown: 1.0,
	expInternet: 1.0, expInternal: 0.6, expUnknown: 1.0,
	scoresLifecycle: true,
	lifeProduction:  1.0, lifeImp: 0.8, lifeStock: 0.3, lifeUnknown: 1.0,
	defaultCVSS: 0.7,
}

// Model3 weighs the severity by ExploitSignal instead of adding EPSS and KEV
// to it, takes the higher of Criticality and Information Classification as
// the impact, softens the multipliers and sets the Score Bands (ADR 0032).
var Model3 = Model{
	version:               3,
	weighsByExploitSignal: true, epssSaturation: 0.10, unexploitedShare: 0.5,
	critHigh: 1.0, critMedium: 0.75, critLow: 0.5, critUnknown: 1.0,
	scoresClassification: true,
	classConfidential:    1.0, classPrivate: 0.75, classPub: 0.5,
	expInternet: 1.0, expInternal: 0.7, expUnknown: 1.0,
	scoresLifecycle: true,
	lifeProduction:  1.0, lifeImp: 0.85, lifeStock: 0.4, lifeUnknown: 1.0,
	defaultCVSS: 0.7,
	bands: []bandFloor{
		{BandCritical, 0.70},
		{BandHigh, 0.40},
		{BandMedium, 0.20},
		{BandLow, 0},
	},
}

func (m Model) Version() ModelVersion { return m.version }

// Band is a Score Band (ADR 0032). It is derived from a Score's value and
// Model, never stored.
type Band int

const (
	BandLow      Band = 1
	BandMedium   Band = 2
	BandHigh     Band = 3
	BandCritical Band = 4
)

func (b Band) String() string {
	switch b {
	case BandLow:
		return "low"
	case BandMedium:
		return "medium"
	case BandHigh:
		return "high"
	case BandCritical:
		return "critical"
	default:
		return fmt.Sprintf("Band(%d)", int(b))
	}
}

// models are the published Scoring Models, so a stored Score's Band is read
// from the Model that scored it.
var models = []Model{Model1, Model2, Model3}

// Band is the Score Band of s under the Model that scored it, and false when
// that Model has none or is not one of the published Models.
func (s Score) Band() (Band, bool) {
	for _, m := range models {
		if m.version == s.Model {
			return m.Band(s.Value)
		}
	}
	return 0, false
}

// bandDigits is how many decimals of a Score its Band is read from: those
// the Dossier and the API show, so a Score shown as 0.7 is never High, and
// the float error of a product that lands on a floor, such as CVSS 7 on a
// KEV CVE and an Asset factor of 1, does not move it (ADR 0032).
const bandDigits = 4

// Band is the Score Band of value under m, and false for a Model that has
// none (Models 1 and 2).
func (m Model) Band(value float64) (Band, bool) {
	scale := math.Pow10(bandDigits)
	shown := math.Round(value*scale) / scale
	for _, b := range m.bands {
		if shown >= b.floor {
			return b.band, true
		}
	}
	return 0, false
}

type Factors struct {
	Alpha, Beta, Gamma    float64 // normalized CVSS, EPSS and KEV
	Vulnerability         float64 // S, layer 1
	CriticalityMultiplier float64
	ExposureMultiplier    float64
	LifecycleMultiplier   float64 // 1 in a Model without a lifecycle factor
	// ExploitSignal is nil in a Model that adds EPSS and KEV instead.
	ExploitSignal *float64
	// ClassificationMultiplier is nil in a Model that does not score the
	// Information Classification, and when the Asset is Unclassified.
	ClassificationMultiplier *float64
}

// Equal reports whether f and g hold the same factors, comparing the
// optional ones by value.
func (f Factors) Equal(g Factors) bool {
	plainF, plainG := f, g
	plainF.ExploitSignal, plainF.ClassificationMultiplier = nil, nil
	plainG.ExploitSignal, plainG.ClassificationMultiplier = nil, nil
	return plainF == plainG && sameOptional(f.ExploitSignal, g.ExploitSignal) &&
		sameOptional(f.ClassificationMultiplier, g.ClassificationMultiplier)
}

func sameOptional(a, b *float64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// Impact is the Asset's impact multiplier: Criticality's, or the
// Information Classification's when it is higher (ADR 0032).
func (f Factors) Impact() float64 {
	if f.ClassificationMultiplier != nil && *f.ClassificationMultiplier > f.CriticalityMultiplier {
		return *f.ClassificationMultiplier
	}
	return f.CriticalityMultiplier
}

type Score struct {
	Model   ModelVersion
	Value   float64 // S_f, 0–1
	Factors Factors
	Gaps    []DataGap // in catalog order
}

// Compute is pure: the same Model and Inputs always give the same Score.
// It fails only on out-of-range inputs, never on missing ones.
func (m Model) Compute(in Inputs) (Score, error) {
	var gaps []DataGap
	var f Factors

	switch {
	case in.CVSS == nil:
		f.Alpha = m.defaultCVSS
		gaps = append(gaps, CVSSEstimated)
	case !(*in.CVSS >= 0 && *in.CVSS <= 10): // also rejects NaN
		return Score{}, fmt.Errorf("%w: %v", ErrInvalidCVSS, *in.CVSS)
	default:
		f.Alpha = *in.CVSS / 10
	}

	switch {
	case in.EPSS == nil:
		gaps = append(gaps, EPSSPending)
	case !(*in.EPSS >= 0 && *in.EPSS <= 1):
		return Score{}, fmt.Errorf("%w: %v", ErrInvalidEPSS, *in.EPSS)
	default:
		f.Beta = *in.EPSS
	}

	if in.KEVListed {
		f.Gamma = 1
	}
	if in.KEVStale {
		gaps = append(gaps, KEVStale)
	}

	var err error
	if f.CriticalityMultiplier, gaps, err = m.criticality(in.Criticality, gaps); err != nil {
		return Score{}, err
	}
	if f.ExposureMultiplier, gaps, err = m.exposure(in.Exposure, gaps); err != nil {
		return Score{}, err
	}
	if f.LifecycleMultiplier, gaps, err = m.lifecycle(in.Lifecycle, gaps); err != nil {
		return Score{}, err
	}
	if f.ClassificationMultiplier, gaps, err = m.classification(in.Classification, gaps); err != nil {
		return Score{}, err
	}

	f.Vulnerability, f.ExploitSignal = m.vulnerability(f)
	return Score{
		Model:   m.version,
		Value:   f.Vulnerability * f.Impact() * f.ExposureMultiplier * f.LifecycleMultiplier,
		Factors: f,
		Gaps:    gaps,
	}, nil
}

// vulnerability is layer 1: the weighted sum of ADR 0009, or the severity
// weighed by ExploitSignal, which is 1 on a KEV CVE and grows linearly with
// EPSS up to epssSaturation (ADR 0032).
func (m Model) vulnerability(f Factors) (float64, *float64) {
	if !m.weighsByExploitSignal {
		return m.wCVSS*f.Alpha + m.wEPSS*f.Beta + m.wKEV*f.Gamma, nil
	}
	exploitSignal := 1.0
	if f.Gamma != 1 {
		exploitSignal = min(f.Beta/m.epssSaturation, 1)
	}
	return f.Alpha * (m.unexploitedShare + (1-m.unexploitedShare)*exploitSignal), &exploitSignal
}

func (m Model) classification(c inventory.InformationClassification, gaps []DataGap) (*float64, []DataGap, error) {
	if !m.scoresClassification {
		return nil, gaps, nil
	}
	var v float64
	switch c {
	case inventory.ClassifiedConfidential:
		v = m.classConfidential
	case inventory.ClassifiedPrivate:
		v = m.classPrivate
	case inventory.ClassifiedPublic:
		v = m.classPub
	case inventory.Unclassified:
		return nil, append(gaps, ClassificationUndeclared), nil
	default:
		return nil, nil, fmt.Errorf("%w: %d", inventory.ErrInvalidInformationClassification, int(c))
	}
	return &v, gaps, nil
}

func (m Model) criticality(c inventory.Criticality, gaps []DataGap) (float64, []DataGap, error) {
	switch c {
	case inventory.CriticalityHigh:
		return m.critHigh, gaps, nil
	case inventory.CriticalityMedium:
		return m.critMedium, gaps, nil
	case inventory.CriticalityLow:
		return m.critLow, gaps, nil
	case inventory.CriticalityUnknown:
		return m.critUnknown, append(gaps, CriticalityUnknown), nil
	default:
		return 0, nil, fmt.Errorf("%w: %d", inventory.ErrInvalidCriticality, int(c))
	}
}

func (m Model) exposure(e inventory.Exposure, gaps []DataGap) (float64, []DataGap, error) {
	switch e {
	case inventory.InternetFacing:
		return m.expInternet, gaps, nil
	case inventory.Internal:
		return m.expInternal, gaps, nil
	case inventory.ExposureUnknown:
		return m.expUnknown, append(gaps, ExposureUndeclared), nil
	default:
		return 0, nil, fmt.Errorf("%w: %d", inventory.ErrInvalidExposure, int(e))
	}
}

func (m Model) lifecycle(s inventory.LifecycleStage, gaps []DataGap) (float64, []DataGap, error) {
	if !m.scoresLifecycle {
		return 1, gaps, nil
	}
	switch s {
	case inventory.LifecycleProduction:
		return m.lifeProduction, gaps, nil
	case inventory.LifecycleImplementation:
		return m.lifeImp, gaps, nil
	case inventory.LifecycleStock:
		return m.lifeStock, gaps, nil
	case inventory.LifecycleUnknown:
		return m.lifeUnknown, append(gaps, LifecycleUnknown), nil
	default:
		return 0, nil, fmt.Errorf("%w: %d", inventory.ErrInvalidLifecycleStage, int(s))
	}
}
