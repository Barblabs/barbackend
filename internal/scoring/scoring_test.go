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
			name:      "kev listed on internet-facing high asset",
			in:        scoring.Inputs{CVSS: ptr(9.8), EPSS: ptr(0.9), KEVListed: true, Criticality: inventory.CriticalityHigh, Exposure: inventory.InternetFacing},
			wantValue: 0.964,
		},
		{
			name:      "multipliers apply to layer 1",
			in:        scoring.Inputs{CVSS: ptr(5), EPSS: ptr(0.002), Criticality: inventory.CriticalityMedium, Exposure: inventory.Internal},
			wantValue: 0.1506 * 0.7 * 0.6,
		},
		{
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

func TestModel1IgnoresLifecycleStage(t *testing.T) {
	in := scoring.Inputs{CVSS: ptr(10), EPSS: ptr(1), KEVListed: true, Criticality: inventory.CriticalityHigh, Exposure: inventory.InternetFacing}
	for _, stage := range []inventory.LifecycleStage{inventory.LifecycleUnknown, inventory.LifecycleStock, 42} {
		in.Lifecycle = stage
		got, err := scoring.Model1.Compute(in)
		if err != nil {
			t.Fatalf("Compute with %v: %v", stage, err)
		}
		if got.Value != 1 || got.Factors.LifecycleMultiplier != 1 || len(got.Gaps) != 0 {
			t.Errorf("Compute with %v = %+v, want Value 1, lifecycle multiplier 1 and no gaps", stage, got)
		}
	}
}

func TestModel2Compute(t *testing.T) {
	worst := scoring.Inputs{CVSS: ptr(10), EPSS: ptr(1), KEVListed: true, Criticality: inventory.CriticalityHigh, Exposure: inventory.InternetFacing}
	tests := []struct {
		name           string
		stage          inventory.LifecycleStage
		wantMultiplier float64
		wantGaps       []scoring.DataGap
	}{
		{"production", inventory.LifecycleProduction, 1, nil},
		{"implementation", inventory.LifecycleImplementation, 0.8, nil},
		{"stock", inventory.LifecycleStock, 0.3, nil},
		{"unknown takes the highest and is a gap", inventory.LifecycleUnknown, 1, []scoring.DataGap{scoring.LifecycleUnknown}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := worst
			in.Lifecycle = tt.stage
			got, err := scoring.Model2.Compute(in)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if got.Factors.LifecycleMultiplier != tt.wantMultiplier || math.Abs(got.Value-tt.wantMultiplier) > 1e-9 {
				t.Errorf("multiplier, Value = %v, %v, want %v for both", got.Factors.LifecycleMultiplier, got.Value, tt.wantMultiplier)
			}
			if !slices.Equal(got.Gaps, tt.wantGaps) {
				t.Errorf("Gaps = %v, want %v", got.Gaps, tt.wantGaps)
			}
			if got.Model != 2 {
				t.Errorf("Model = %v, want 2", got.Model)
			}
		})
	}
}

func TestModel2MultipliesEveryLayer(t *testing.T) {
	in := scoring.Inputs{
		CVSS: ptr(5), EPSS: ptr(0.002), Criticality: inventory.CriticalityMedium, Exposure: inventory.Internal,
		Lifecycle: inventory.LifecycleImplementation,
	}
	got, err := scoring.Model2.Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	if want := 0.1506 * 0.7 * 0.6 * 0.8; math.Abs(got.Value-want) > 1e-9 {
		t.Errorf("Value = %v, want %v", got.Value, want)
	}
}

func TestModel2IgnoresInformationClassification(t *testing.T) {
	in := scoring.Inputs{CVSS: ptr(5), EPSS: ptr(0.002), Criticality: inventory.CriticalityLow, Exposure: inventory.Internal, Lifecycle: inventory.LifecycleProduction}
	for _, c := range []inventory.InformationClassification{inventory.Unclassified, inventory.ClassifiedConfidential, 42} {
		in.Classification = c
		got, err := scoring.Model2.Compute(in)
		if err != nil {
			t.Fatalf("Compute with %v: %v", c, err)
		}
		if want := 0.1506 * 0.4 * 0.6; math.Abs(got.Value-want) > 1e-9 || got.Factors.ClassificationMultiplier != nil || got.Factors.ExploitSignal != nil || len(got.Gaps) != 0 {
			t.Errorf("Compute with %v = %+v, want Value %v, no classification multiplier or exploit signal and no gaps", c, got, want)
		}
	}
}

func TestModel3ComputeTheExamplesOfADR0032(t *testing.T) {
	tests := []struct {
		name      string
		in        scoring.Inputs
		wantValue float64
		wantBand  scoring.Band
		wantGaps  []scoring.DataGap
	}{
		{
			name: "kev on a confidential internet-facing production asset",
			in: scoring.Inputs{CVSS: ptr(10), EPSS: ptr(0.94), KEVListed: true, Criticality: inventory.CriticalityHigh,
				Classification: inventory.ClassifiedConfidential, Exposure: inventory.InternetFacing, Lifecycle: inventory.LifecycleProduction},
			wantValue: 1, wantBand: scoring.BandCritical,
		},
		{
			name: "severe with no sign of exploitation",
			in: scoring.Inputs{CVSS: ptr(9.8), EPSS: ptr(0.02), Criticality: inventory.CriticalityHigh,
				Exposure: inventory.InternetFacing, Lifecycle: inventory.LifecycleProduction},
			wantValue: 0.98 * 0.6, wantBand: scoring.BandHigh,
			wantGaps: []scoring.DataGap{scoring.ClassificationUndeclared},
		},
		{
			name: "confidential raises a low asset",
			in: scoring.Inputs{CVSS: ptr(8.8), EPSS: ptr(0.5), KEVListed: true, Criticality: inventory.CriticalityLow,
				Classification: inventory.ClassifiedConfidential, Exposure: inventory.Internal, Lifecycle: inventory.LifecycleProduction},
			wantValue: 0.88 * 0.7, wantBand: scoring.BandHigh,
		},
		{
			name: "unclassified leaves the impact to criticality",
			in: scoring.Inputs{CVSS: ptr(8.8), EPSS: ptr(0.5), KEVListed: true, Criticality: inventory.CriticalityLow,
				Exposure: inventory.Internal, Lifecycle: inventory.LifecycleProduction},
			wantValue: 0.88 * 0.5 * 0.7, wantBand: scoring.BandMedium,
			wantGaps: []scoring.DataGap{scoring.ClassificationUndeclared},
		},
		{
			name: "the typical finding",
			in: scoring.Inputs{CVSS: ptr(7.5), EPSS: ptr(0.01), Criticality: inventory.CriticalityMedium,
				Classification: inventory.ClassifiedPrivate, Exposure: inventory.Internal, Lifecycle: inventory.LifecycleProduction},
			wantValue: 0.75 * 0.55 * 0.75 * 0.7, wantBand: scoring.BandMedium,
		},
		{
			name: "epss above the saturation counts in full",
			in: scoring.Inputs{CVSS: ptr(6.1), EPSS: ptr(0.35), Criticality: inventory.CriticalityMedium,
				Classification: inventory.ClassifiedPublic, Exposure: inventory.InternetFacing, Lifecycle: inventory.LifecycleProduction},
			wantValue: 0.61 * 0.75, wantBand: scoring.BandHigh,
		},
		{
			name: "kev on a spare in stock",
			in: scoring.Inputs{CVSS: ptr(9.8), EPSS: ptr(0.9), KEVListed: true, Criticality: inventory.CriticalityHigh,
				Exposure: inventory.Internal, Lifecycle: inventory.LifecycleStock},
			wantValue: 0.98 * 0.7 * 0.4, wantBand: scoring.BandMedium,
			wantGaps: []scoring.DataGap{scoring.ClassificationUndeclared},
		},
		{
			name: "the lowest asset factor",
			in: scoring.Inputs{CVSS: ptr(5.3), EPSS: ptr(0.001), Criticality: inventory.CriticalityLow,
				Classification: inventory.ClassifiedPublic, Exposure: inventory.Internal, Lifecycle: inventory.LifecycleStock},
			wantValue: 0.53 * 0.505 * 0.5 * 0.7 * 0.4, wantBand: scoring.BandLow,
		},
		{
			name:      "no data at all takes every default and records every gap",
			in:        scoring.Inputs{},
			wantValue: 0.35, wantBand: scoring.BandMedium,
			wantGaps: []scoring.DataGap{
				scoring.CVSSEstimated, scoring.EPSSPending, scoring.CriticalityUnknown,
				scoring.ExposureUndeclared, scoring.LifecycleUnknown, scoring.ClassificationUndeclared,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scoring.Model3.Compute(tt.in)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if math.Abs(got.Value-tt.wantValue) > 1e-9 {
				t.Errorf("Value = %v, want %v", got.Value, tt.wantValue)
			}
			if !slices.Equal(got.Gaps, tt.wantGaps) {
				t.Errorf("Gaps = %v, want %v", got.Gaps, tt.wantGaps)
			}
			if got.Model != 3 {
				t.Errorf("Model = %v, want 3", got.Model)
			}
			if band, ok := scoring.Model3.Band(got.Value); !ok || band != tt.wantBand {
				t.Errorf("Band = %v, %v, want %v", band, ok, tt.wantBand)
			}
		})
	}
}

func TestModel3ExploitSignal(t *testing.T) {
	tests := []struct {
		name string
		in   scoring.Inputs
		want float64
	}{
		{"kev counts in full whatever the epss", scoring.Inputs{EPSS: ptr(0), KEVListed: true}, 1},
		{"epss grows linearly", scoring.Inputs{EPSS: ptr(0.05)}, 0.5},
		{"epss saturates at 10%", scoring.Inputs{EPSS: ptr(0.10)}, 1},
		{"epss above 10% counts the same", scoring.Inputs{EPSS: ptr(0.9)}, 1},
		{"pending epss is no sign of exploitation", scoring.Inputs{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.in.CVSS = ptr(10)
			got, err := scoring.Model3.Compute(tt.in)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if got.Factors.ExploitSignal == nil || math.Abs(*got.Factors.ExploitSignal-tt.want) > 1e-9 {
				t.Fatalf("ExploitSignal = %v, want %v", got.Factors.ExploitSignal, tt.want)
			}
			if want := 0.5 + 0.5*tt.want; math.Abs(got.Factors.Vulnerability-want) > 1e-9 {
				t.Errorf("Vulnerability = %v, want %v", got.Factors.Vulnerability, want)
			}
		})
	}
}

func TestModel3ImpactIsTheHigherOfCriticalityAndClassification(t *testing.T) {
	tests := []struct {
		name           string
		criticality    inventory.Criticality
		classification inventory.InformationClassification
		want           float64
	}{
		{"public never lowers a high asset", inventory.CriticalityHigh, inventory.ClassifiedPublic, 1},
		{"confidential raises a low asset", inventory.CriticalityLow, inventory.ClassifiedConfidential, 1},
		{"private raises a low asset to medium", inventory.CriticalityLow, inventory.ClassifiedPrivate, 0.75},
		{"unclassified does not count", inventory.CriticalityLow, inventory.Unclassified, 0.5},
		{"unknown criticality takes the highest", inventory.CriticalityUnknown, inventory.ClassifiedPublic, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := scoring.Inputs{
				CVSS: ptr(10), EPSS: ptr(0), KEVListed: true, Criticality: tt.criticality, Classification: tt.classification,
				Exposure: inventory.InternetFacing, Lifecycle: inventory.LifecycleProduction,
			}
			got, err := scoring.Model3.Compute(in)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if got.Factors.Impact() != tt.want || math.Abs(got.Value-tt.want) > 1e-9 {
				t.Errorf("Impact, Value = %v, %v, want %v for both", got.Factors.Impact(), got.Value, tt.want)
			}
		})
	}
}

func TestModel3RejectsOutOfRangeClassification(t *testing.T) {
	in := scoring.Inputs{CVSS: ptr(5), EPSS: ptr(0.5), Criticality: inventory.CriticalityHigh, Exposure: inventory.Internal, Classification: 42}
	if _, err := scoring.Model3.Compute(in); !errors.Is(err, inventory.ErrInvalidInformationClassification) {
		t.Errorf("err = %v, want %v", err, inventory.ErrInvalidInformationClassification)
	}
}

func TestModel3Band(t *testing.T) {
	tests := []struct {
		value float64
		want  scoring.Band
	}{
		{1, scoring.BandCritical},
		{0.70, scoring.BandCritical},
		{0.6999, scoring.BandHigh},
		{0.40, scoring.BandHigh},
		{0.3999, scoring.BandMedium},
		{0.20, scoring.BandMedium},
		{0.1999, scoring.BandLow},
		{0, scoring.BandLow},
	}
	for _, tt := range tests {
		if got, ok := scoring.Model3.Band(tt.value); !ok || got != tt.want {
			t.Errorf("Band(%v) = %v, %v, want %v", tt.value, got, ok, tt.want)
		}
	}
}

func TestModel3BandHoldsAFloorReachedByAProduct(t *testing.T) {
	in := scoring.Inputs{
		CVSS: ptr(7), EPSS: ptr(0), KEVListed: true, Criticality: inventory.CriticalityHigh,
		Exposure: inventory.InternetFacing, Lifecycle: inventory.LifecycleProduction,
	}
	got, err := scoring.Model3.Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	if band, _ := scoring.Model3.Band(got.Value); band != scoring.BandCritical {
		t.Errorf("Band(%v) = %v, want critical", got.Value, band)
	}
}

func TestAScoreHasTheBandOfTheModelThatScoredIt(t *testing.T) {
	tests := []struct {
		name   string
		score  scoring.Score
		want   scoring.Band
		wantOK bool
	}{
		{"model 3", scoring.Score{Model: 3, Value: 0.59}, scoring.BandHigh, true},
		{"model 2 has none", scoring.Score{Model: 2, Value: 0.59}, 0, false},
		{"an unpublished model has none", scoring.Score{Model: 42, Value: 0.59}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, ok := tt.score.Band(); got != tt.want || ok != tt.wantOK {
				t.Errorf("Band = %v, %v, want %v, %v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestModelsBeforeModel3HaveNoBand(t *testing.T) {
	for _, m := range []scoring.Model{scoring.Model1, scoring.Model2} {
		if band, ok := m.Band(1); ok {
			t.Errorf("Model %v Band(1) = %v, want none", m.Version(), band)
		}
	}
}

func TestModel2RejectsOutOfRangeLifecycleStage(t *testing.T) {
	in := scoring.Inputs{CVSS: ptr(5), EPSS: ptr(0.5), Criticality: inventory.CriticalityHigh, Exposure: inventory.Internal, Lifecycle: 42}
	if _, err := scoring.Model2.Compute(in); !errors.Is(err, inventory.ErrInvalidLifecycleStage) {
		t.Errorf("err = %v, want %v", err, inventory.ErrInvalidLifecycleStage)
	}
}
