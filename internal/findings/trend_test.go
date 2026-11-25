package findings_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"barbackend/internal/findings"
	"barbackend/internal/inventory"
)

func TestWeeklyTrendCountsFirstOpensAndClosesInEveryWeek(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.sync(t,
		server(t, "a", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0")),
		server(t, "b", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0")),
		server(t, "c", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0")),
	)
	w.handleNVD(t, nvdVulnerability(t, "CVE-2021-23017", "Analyzed", nginxBefore1201))
	day := func(month time.Month, d int) time.Time { return time.Date(2026, month, d, 10, 0, 0, 0, time.UTC) }
	w.setHistory(t, "a", day(time.November, 3), time.Time{})                            // opened in W45
	w.setHistory(t, "b", day(time.October, 20), day(time.November, 10))                 // opened before, closed in W46
	w.setHistory(t, "c", day(time.November, 17), day(time.November, 18).Add(time.Hour)) // both in W47
	w.findings.SetNow(func() time.Time { return day(time.November, 18).Add(5 * time.Hour) })

	trend, err := w.findings.WeeklyTrend(context.Background(), w.viewer(t), 3)
	if err != nil {
		t.Fatal(err)
	}

	want := []findings.Week{
		{Start: time.Date(2026, time.November, 2, 0, 0, 0, 0, time.UTC), Opened: 1, OpenAtEnd: 2},
		{Start: time.Date(2026, time.November, 9, 0, 0, 0, 0, time.UTC), Closed: 1, OpenAtEnd: 1},
		{Start: time.Date(2026, time.November, 16, 0, 0, 0, 0, time.UTC), Opened: 1, Closed: 1, OpenAtEnd: 1},
	}
	if len(trend) != len(want) {
		t.Fatalf("trend = %+v, want %+v", trend, want)
	}
	for i := range want {
		if !trend[i].Start.Equal(want[i].Start) || trend[i].Opened != want[i].Opened || trend[i].Closed != want[i].Closed || trend[i].OpenAtEnd != want[i].OpenAtEnd {
			t.Errorf("week %d = %+v, want %+v", i, trend[i], want[i])
		}
	}
}

func TestWeeklyTrendFillsQuietWeeksAndDefaultsToTwelve(t *testing.T) {
	t.Parallel()
	w := newWorld(t)

	trend, err := w.findings.WeeklyTrend(context.Background(), w.viewer(t), 0)
	if err != nil {
		t.Fatal(err)
	}

	if len(trend) != findings.DefaultTrendWeeks {
		t.Fatalf("weeks = %d, want %d", len(trend), findings.DefaultTrendWeeks)
	}
	for i, week := range trend {
		if week.Opened != 0 || week.Closed != 0 || week.Start.Weekday() != time.Monday {
			t.Errorf("week %d = %+v, want a Monday with nothing opened or closed", i, week)
		}
	}
}

func TestWeeklyTrendRefusesWeeksOutOfRange(t *testing.T) {
	t.Parallel()
	w := newWorld(t)

	for _, weeks := range []int{-1, findings.MaxTrendWeeks + 1} {
		if _, err := w.findings.WeeklyTrend(context.Background(), w.viewer(t), weeks); !errors.Is(err, findings.ErrInvalidTrend) {
			t.Errorf("%d weeks: err = %v, want ErrInvalidTrend", weeks, err)
		}
	}
}

func TestWeeklyTrendCountsTheCurrentWeeksCriticalAsTheSummaryDoes(t *testing.T) {
	t.Parallel()
	w := countedWorld(t)
	w.exec(t, `UPDATE finding_scores SET model = 2, value = 0.95 WHERE finding_id = (SELECT id FROM findings WHERE record_id = 'b')`)

	trend, err := w.findings.WeeklyTrend(context.Background(), w.viewer(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := w.findings.Summary(context.Background(), w.viewer(t))
	if err != nil {
		t.Fatal(err)
	}

	if got := trend[0].CriticalOpenAtEnd; got != 1 || got != sum.Bands.Critical {
		t.Errorf("critical open at end = %d, summary critical = %d, want both 1: b's Model 2 Score has no Band", got, sum.Bands.Critical)
	}
}

func TestWeeklyTrendCountsAFindingCriticalOnlyFromTheWeekItsScoreBecameCritical(t *testing.T) {
	t.Parallel()
	w, _ := matchedPayments(t)
	day := func(d int) time.Time { return time.Date(2026, time.November, d, 10, 0, 0, 0, time.UTC) }
	w.setHistory(t, "payments", day(3), time.Time{})
	w.scoreHistory(t, "payments", high(day(4)), critical(day(17)))
	w.findings.SetNow(func() time.Time { return day(18) })

	trend, err := w.findings.WeeklyTrend(context.Background(), w.viewer(t), 2)
	if err != nil {
		t.Fatal(err)
	}

	if len(trend) != 2 || trend[0].CriticalOpenAtEnd != 0 || trend[1].CriticalOpenAtEnd != 1 {
		t.Errorf("trend = %+v, want 0 Critical at the end of W46, while High, then 1 in W47", trend)
	}
}
