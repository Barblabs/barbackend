package scoring_test

import (
	"errors"
	"math"
	"slices"
	"testing"

	"barbackend/internal/inventory"
	"barbackend/internal/scoring"
)

func ptr(v float64) *float64 { return &v }

func TestModel1Compute(t *testing.T) {
	tests := []struct {
		name      string
		in        scoring.Inputs
		wantValue float64
		wantGaps  []scoring.DataGap
	}{
		{
			name:      "all known, worst case",
			in:        scoring.Inputs{CVSS: ptr(10), EPSS: ptr(1), KEVListed: true, Criticality: inventory.CriticalityHigh, Exposure: inventory.InternetFacing},
			wantValue: 1,
		},
		{
			name:      "all known, best case",
			in:        scoring.Inputs{CVSS: ptr(0), EPSS: ptr(0), Criticality: inventory.CriticalityLow, Exposure: inventory.Internal},
			wantValue: 0,
		},
		{
			// 0.3·0.98 + 0.3·0.9 + 0.4·1 = 0.964
			name:      "kev listed on internet-facing high asset",
			in:        scoring.Inputs{CVSS: ptr(9.8), EPSS: ptr(0.9), KEVListed: true, Criticality: inventory.CriticalityHigh, Exposure: inventory.InternetFacing},
			wantValue: 0.964,
		},
		{
			// (0.3·0.5 + 0.3·0.002) · 0.7 · 0.6
			name:      "multipliers apply to layer 1",
			in:        scoring.Inputs{CVSS: ptr(5), EPSS: ptr(0.002), Criticality: inventory.CriticalityMedium, Exposure: inventory.Internal},
			wantValue: 0.1506 * 0.7 * 0.6,
		},
		{
			// 0.3·0.7 + 0 + 0, both multipliers 1.0
			name:      "zero inputs are every gap and never lower the score",
			in:        scoring.Inputs{KEVStale: true},
			wantValue: 0.21,
			wantGaps:  []scoring.DataGap{scoring.CVSSEstimated, scoring.EPSSPending, scoring.KEVStale, scoring.CriticalityUnknown, scoring.ExposureUndeclared},
		},
		{
			name:      "stale catalog keeps the last listing",
			in:        scoring.Inputs{CVSS: ptr(0), EPSS: ptr(0), KEVListed: true, KEVStale: true, Criticality: inventory.CriticalityHigh, Exposure: inventory.InternetFacing},
			wantValue: 0.4,
			wantGaps:  []scoring.DataGap{scoring.KEVStale},
		},
		{
			name:      "epss zero is not pending",
			in:        scoring.Inputs{CVSS: ptr(10), EPSS: ptr(0), Criticality: inventory.CriticalityHigh, Exposure: inventory.InternetFacing},
			wantValue: 0.3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scoring.Model1.Compute(tt.in)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if math.Abs(got.Value-tt.wantValue) > 1e-9 {
				t.Errorf("Value = %v, want %v", got.Value, tt.wantValue)
			}
			if !slices.Equal(got.Gaps, tt.wantGaps) {
				t.Errorf("Gaps = %v, want %v", got.Gaps, tt.wantGaps)
			}
			if got.Model != scoring.Model1.Version() {
				t.Errorf("Model = %v, want %v", got.Model, scoring.Model1.Version())
			}
		})
	}
}

func TestModel1ComputeRejectsOutOfRange(t *testing.T) {
	valid := scoring.Inputs{CVSS: ptr(5), EPSS: ptr(0.5), Criticality: inventory.CriticalityHigh, Exposure: inventory.Internal}
	tests := []struct {
		name   string
		mutate func(*scoring.Inputs)
		want   error
	}{
		{"cvss above 10", func(in *scoring.Inputs) { in.CVSS = ptr(10.1) }, scoring.ErrInvalidCVSS},
		{"cvss negative", func(in *scoring.Inputs) { in.CVSS = ptr(-1) }, scoring.ErrInvalidCVSS},
		{"cvss NaN", func(in *scoring.Inputs) { in.CVSS = ptr(math.NaN()) }, scoring.ErrInvalidCVSS},
		{"epss above 1", func(in *scoring.Inputs) { in.EPSS = ptr(1.5) }, scoring.ErrInvalidEPSS},
		{"epss percentile passed by mistake", func(in *scoring.Inputs) { in.EPSS = ptr(95) }, scoring.ErrInvalidEPSS},
		{"criticality out of range", func(in *scoring.Inputs) { in.Criticality = 42 }, inventory.ErrInvalidCriticality},
		{"exposure out of range", func(in *scoring.Inputs) { in.Exposure = 42 }, inventory.ErrInvalidExposure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := valid
			tt.mutate(&in)
			if _, err := scoring.Model1.Compute(in); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}
