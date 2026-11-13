// Package scoring computes the Score of a Finding with a versioned Scoring Model (ADR 0009).
package scoring

import (
	"errors"
	"fmt"

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

func (m Model) Version() ModelVersion { return m.version }

type Factors struct {
	Alpha, Beta, Gamma    float64 // normalized CVSS, EPSS and KEV
	Vulnerability         float64 // S, layer 1
	CriticalityMultiplier float64
	ExposureMultiplier    float64
	LifecycleMultiplier   float64 // 1 in a Model without a lifecycle factor
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

	f.Vulnerability = m.wCVSS*f.Alpha + m.wEPSS*f.Beta + m.wKEV*f.Gamma
	return Score{
		Model:   m.version,
		Value:   f.Vulnerability * f.CriticalityMultiplier * f.ExposureMultiplier * f.LifecycleMultiplier,
		Factors: f,
		Gaps:    gaps,
	}, nil
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
