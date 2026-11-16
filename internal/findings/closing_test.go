package findings_test

import (
	"context"
	"testing"
	"time"

	"barbackend/internal/findings"
)

func TestTimeToCloseMeasuresTheFindingsClosedInTheWindowByBand(t *testing.T) {
	t.Parallel()
	w := countedWorld(t)
	day := func(d int) time.Time { return time.Date(2026, time.November, d, 10, 0, 0, 0, time.UTC) }
	w.setHistory(t, "a", day(3), day(7))  // its Critical and Medium Findings, 4 days each
	w.setHistory(t, "b", day(9), day(15)) // its High Finding, 6 days
	w.findings.SetNow(func() time.Time { return day(18) })

	three, err := w.findings.TimeToClose(context.Background(), w.viewer(t), 3)
	if err != nil {
		t.Fatal(err)
	}
	current, err := w.findings.TimeToClose(context.Background(), w.viewer(t), 1)
	if err != nil {
		t.Fatal(err)
	}

	four, six := 4*24*time.Hour, 6*24*time.Hour
	want := findings.TimesToClose{
		Critical: findings.CloseTime{Closed: 1, Median: four, Average: four},
		High:     findings.CloseTime{Closed: 1, Median: six, Average: six},
		Medium:   findings.CloseTime{Closed: 1, Median: four, Average: four},
	}
	if three != want {
		t.Errorf("three weeks = %+v, want %+v", three, want)
	}
	if current != (findings.TimesToClose{}) {
		t.Errorf("current week = %+v, want nothing closed in it", current)
	}
}

func TestCloseTimeTakesTheMiddleOfAnEvenCountAsMedian(t *testing.T) {
	t.Parallel()

	got := findings.CloseTimeOf([]time.Duration{9 * time.Hour, time.Hour, 3 * time.Hour, 100 * time.Hour})

	if want := (findings.CloseTime{Closed: 4, Median: 6 * time.Hour, Average: 113 * time.Hour / 4}); got != want {
		t.Errorf("close time = %+v, want %+v", got, want)
	}
}
