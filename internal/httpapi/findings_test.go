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

func TestFindingCountsOfACustomerWithoutFindingsAreZeros(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	get := func(path string) *httptest.ResponseRecorder {
		return e.do(httptest.NewRequest(http.MethodGet, path, nil))
	}

	summary := decode[map[string]int](t, get("/findings/summary"), http.StatusOK)
	exposure := decode[struct {
		By     string `json:"by"`
		Groups []struct {
			Value    string  `json:"value"`
			Name     *string `json:"name"`
			Critical *int    `json:"critical"`
		} `json:"groups"`
	}](t, get("/findings/breakdown"), http.StatusOK)
	top := decode[struct {
		Components *[]struct{} `json:"components"`
		CVEs       *[]struct{} `json:"cves"`
	}](t, get("/findings/top"), http.StatusOK)

	for _, key := range []string{"open", "critical", "high", "medium", "low", "unbanded", "kev", "critical_internet_facing"} {
		if n, ok := summary[key]; !ok || n != 0 {
			t.Errorf("summary %s = %d (present %v), want 0", key, n, ok)
		}
	}
	values := []string{}
	for _, g := range exposure.Groups {
		values = append(values, g.Value)
		if g.Name != nil || g.Critical == nil || *g.Critical != 0 {
			t.Errorf("group %+v, want no name and a zero critical", g)
		}
	}
	if exposure.By != "exposure" || fmt.Sprint(values) != "[internet_facing internal unknown]" {
		t.Errorf("breakdown by %s = %v, want every exposure by default", exposure.By, values)
	}
	if top.Components == nil || len(*top.Components) != 0 || top.CVEs == nil || len(*top.CVEs) != 0 {
		t.Errorf("top = %+v, want two empty lists", top)
	}
}

func TestFindingCountsRefuseAnUnknownGroupingAndTooLongALimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	for _, path := range []string{"/findings/breakdown?by=kind", "/findings/top?limit=51"} {
		if rec := e.do(httptest.NewRequest(http.MethodGet, path, nil)); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d %s, want 400", path, rec.Code, rec.Body)
		}
	}
}
