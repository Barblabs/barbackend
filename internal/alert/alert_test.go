package alert_test

import (
	"cmp"
	"fmt"
	"slices"
	"testing"

	"barbackend/internal/alert"
)

func TestBatchesAreOfTenHighestScoreFirst(t *testing.T) {
	var findings []alert.Finding
	for i := range 23 {
		findings = append(findings, alert.Finding{Finding: fmt.Sprintf("f%02d", i), Score: float64(i%5) / 10})
	}
	batches := alert.Batches(findings)
	if sizes := []int{len(batches[0].Findings), len(batches[1].Findings), len(batches[2].Findings)}; len(batches) != 3 || !slices.Equal(sizes, []int{10, 10, 3}) {
		t.Fatalf("%d batches of %v, want 3 of 10, 10 and 3", len(batches), sizes)
	}
	var all []alert.Finding
	for _, b := range batches {
		all = append(all, b.Findings...)
	}
	if !slices.IsSortedFunc(all, func(a, b alert.Finding) int {
		return cmp.Or(cmp.Compare(b.Score, a.Score), cmp.Compare(a.Finding, b.Finding))
	}) {
		t.Errorf("batches are not by Score, highest first, then by Finding")
	}
}

func TestNoFindingsMakeNoBatch(t *testing.T) {
	if batches := alert.Batches(nil); len(batches) != 0 {
		t.Errorf("Batches(nil) = %v, want none", batches)
	}
}
