package findings_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"barbackend/internal/findings"
	"barbackend/internal/inventory"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
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

func TestWeeklyTrendRefusesWeeksOutOfRangeAndPlatformAdmins(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	staff, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "staff@example.com", tenancy.PlatformAdmin, tenancy.CustomerID{})
	if err != nil {
		t.Fatal(err)
	}

	for _, weeks := range []int{-1, findings.MaxTrendWeeks + 1} {
		if _, err := w.findings.WeeklyTrend(context.Background(), w.viewer(t), weeks); !errors.Is(err, findings.ErrInvalidTrend) {
			t.Errorf("%d weeks: err = %v, want ErrInvalidTrend", weeks, err)
		}
	}
	if _, err := w.findings.WeeklyTrend(context.Background(), staff, 1); !errors.Is(err, tenancy.ErrNoCustomer) {
		t.Errorf("platform admin: err = %v, want ErrNoCustomer", err)
	}
}

// setHistory sets when the record's only Finding was first opened and, unless
// closed is zero, when it was closed.
func (w world) setHistory(t *testing.T, record string, opened, closed time.Time) {
	t.Helper()
	var closedAt *time.Time
	if !closed.IsZero() {
		closedAt = &closed
	}
	w.exec(t, `
		UPDATE findings
		SET first_opened_at = $1, opened_at = $1, closed_at = $2,
		    close_reason_id = CASE WHEN $2::timestamptz IS NULL THEN NULL ELSE 1 END
		WHERE record_id = $3`, opened, closedAt, record)
}

func (w world) viewer(t *testing.T) tenancy.User {
	t.Helper()
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "viewer@example.com", tenancy.Viewer, w.customer)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
