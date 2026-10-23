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
}

type DataGap int

const (
	CVSSEstimated      DataGap = 1
	EPSSPending        DataGap = 2
	KEVStale           DataGap = 3
	CriticalityUnknown DataGap = 4
	ExposureUndeclared DataGap = 5
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
	default:
		return fmt.Sprintf("DataGap(%d)", int(g))
	}
}

type ModelVersion int

type Model struct {
	version                  ModelVersion
	wCVSS, wEPSS, wKEV       float64
	critHigh, critMedium     float64
	critLow, critUnknown     float64
	expInternet, expInternal float64
	expUnknown               float64
	defaultCVSS              float64
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

func (m Model) Version() ModelVersion { return m.version }

type Factors struct {
	Alpha, Beta, Gamma    float64 // normalized CVSS, EPSS and KEV
	Vulnerability         float64 // S, layer 1
	CriticalityMultiplier float64
	ExposureMultiplier    float64
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
	case !inRange(*in.CVSS, 0, 10):
		return Score{}, fmt.Errorf("%w: %v", ErrInvalidCVSS, *in.CVSS)
	default:
		f.Alpha = *in.CVSS / 10
	}

	switch {
	case in.EPSS == nil:
		gaps = append(gaps, EPSSPending)
	case !inRange(*in.EPSS, 0, 1):
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

	switch in.Criticality {
	case inventory.CriticalityHigh:
		f.CriticalityMultiplier = m.critHigh
	case inventory.CriticalityMedium:
		f.CriticalityMultiplier = m.critMedium
	case inventory.CriticalityLow:
		f.CriticalityMultiplier = m.critLow
	case inventory.CriticalityUnknown:
		f.CriticalityMultiplier = m.critUnknown
		gaps = append(gaps, CriticalityUnknown)
	default:
		return Score{}, fmt.Errorf("%w: %d", inventory.ErrInvalidCriticality, int(in.Criticality))
	}

	switch in.Exposure {
	case inventory.InternetFacing:
		f.ExposureMultiplier = m.expInternet
	case inventory.Internal:
		f.ExposureMultiplier = m.expInternal
	case inventory.ExposureUnknown:
		f.ExposureMultiplier = m.expUnknown
		gaps = append(gaps, ExposureUndeclared)
	default:
		return Score{}, fmt.Errorf("%w: %d", inventory.ErrInvalidExposure, int(in.Exposure))
	}

	f.Vulnerability = m.wCVSS*f.Alpha + m.wEPSS*f.Beta + m.wKEV*f.Gamma
	return Score{
		Model:   m.version,
		Value:   f.Vulnerability * f.CriticalityMultiplier * f.ExposureMultiplier,
		Factors: f,
		Gaps:    gaps,
	}, nil
}

func inRange(v, lo, hi float64) bool {
	return !math.IsNaN(v) && v >= lo && v <= hi
}
