package httpapi_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type weeklyTrend struct {
	Weeks []struct {
		Week     string `json:"week"`
		StartsOn string `json:"starts_on"`
		Opened   int    `json:"opened"`
		Closed   int    `json:"closed"`
	} `json:"weeks"`
}

func TestWeeklyTrendHasTwelveWeeksEndingWithTheCurrentOne(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	got := decode[weeklyTrend](t, e.do(httptest.NewRequest(http.MethodGet, "/findings/weekly-trend", nil)), http.StatusOK)

	if len(got.Weeks) != 12 {
		t.Fatalf("weeks = %d, want 12", len(got.Weeks))
	}
	year, week := time.Now().UTC().ISOWeek()
	if last := got.Weeks[11]; last.Week != fmt.Sprintf("%d-W%02d", year, week) || last.Opened != 0 || last.Closed != 0 {
		t.Errorf("last week = %+v, want the current ISO week with nothing opened or closed", last)
	}
	if starts, err := time.Parse(time.DateOnly, got.Weeks[0].StartsOn); err != nil || starts.Weekday() != time.Monday {
		t.Errorf("first week starts on %q, want a Monday", got.Weeks[0].StartsOn)
	}
}

func TestWeeklyTrendRefusesMoreThanAYearOfWeeks(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	if rec := e.do(httptest.NewRequest(http.MethodGet, "/findings/weekly-trend?weeks=53", nil)); rec.Code != http.StatusBadRequest {
		t.Errorf("53 weeks = %d %s, want 400", rec.Code, rec.Body)
	}
}
