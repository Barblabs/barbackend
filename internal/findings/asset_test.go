package findings_test

import (
	"context"
	"slices"
	"testing"

	"barbackend/internal/inventory"
)

func TestRescoreAssetScoresItsOpenFindingsWithTheDeclaredExposure(t *testing.T) {
	t.Parallel()
	w, f := matchedPayments(t)
	payments := inventory.SourceReference{Source: w.source, RecordID: "payments"}
	rescore := func() (multiplier float64, gaps []string, scores int) {
		t.Helper()
		if err := w.findings.RescoreAsset(context.Background(), payments); err != nil {
			t.Fatal(err)
		}
		_, _, gaps, scores = w.latestScore(t, f.id)
		return w.latestExposureMultiplier(t, f.id), gaps, scores
	}

	w.declareExposure(t, "payments", inventory.Internal)
	if m, gaps, scores := rescore(); m != 0.6 || slices.Contains(gaps, "exposure_undeclared") || scores != 2 {
		t.Errorf("declared Internal: multiplier %v, gaps %v, %d scores; want 0.6 without exposure_undeclared in a second score", m, gaps, scores)
	}
	if _, _, scores := rescore(); scores != 2 {
		t.Errorf("rescored unchanged: %d scores, want still 2", scores)
	}

	w.declareExposure(t, "payments", inventory.ExposureUnknown)
	if m, gaps, scores := rescore(); m != 1 || !slices.Contains(gaps, "exposure_undeclared") || scores != 3 {
		t.Errorf("cleared: multiplier %v, gaps %v, %d scores; want 1 with exposure_undeclared in a third score", m, gaps, scores)
	}
}
