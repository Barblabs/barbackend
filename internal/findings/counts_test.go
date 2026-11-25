package findings_test

import (
	"context"
	"testing"

	"barbackend/internal/findings"
)

func TestSummaryCountsOpenFindingsByBandKEVAndCriticalInternetFacing(t *testing.T) {
	t.Parallel()
	w := countedWorld(t)

	sum, err := w.findings.Summary(context.Background(), w.viewer(t))
	if err != nil {
		t.Fatal(err)
	}

	want := findings.Summary{Bands: findings.BandCounts{Critical: 1, High: 1, Medium: 1}, KEV: 2, CriticalInternetFacing: 1}
	if sum != want {
		t.Errorf("summary = %+v, want %+v", sum, want)
	}
}
