package httpapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"barbackend/internal/assessment"
	"barbackend/internal/claude/claudetest"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

type findingHistory struct {
	Entries []struct {
		PrioritizationID string `json:"prioritization_id"`
		Kind             string `json:"kind"`
		GroupBefore      *int   `json:"group_before"`
		GroupNow         *int   `json:"group_now"`
		Title            string `json:"title"`
		Reason           string `json:"reason"`
		Evidence         []struct {
			Path  string `json:"path"`
			Value string `json:"value"`
		} `json:"evidence"`
		Changes []string `json:"changes"`
		Band    *struct {
			From string `json:"from"`
		} `json:"band"`
		Score *struct {
			From float64 `json:"from"`
			To   float64 `json:"to"`
		} `json:"score"`
		Feedback []struct {
			Verdict string `json:"verdict"`
			Note    string `json:"note"`
		} `json:"feedback"`
		GroupsAppeared []string `json:"groups_appeared"`
		CloseReason    *string  `json:"close_reason"`
	} `json:"entries"`
}

func TestFindingHistoryTellsWhyEachFindingMoved(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	f1, f2 := firstAndSecond(p)
	feedback := jsonRequest(t, http.MethodPost, "/prioritizations/"+p.ID.String()+"/feedback", map[string]string{"finding_id": f2, "verdict": "should_be_earlier", "note": "es el de pagos"})
	if rec := e.do(feedback); rec.Code != http.StatusCreated {
		t.Fatalf("feedback = %d %s", rec.Code, rec.Body)
	}
	one := 1
	e.llm.Queue(claudetest.JSON(t, assessment.Placement{Groups: []assessment.PlacedGroup{
		{Title: "Antes", Findings: []string{f2}, Reason: "Es el de pagos.", Evidence: []assessment.FindingEvidence{{Finding: f2, Path: "/kev", Value: "null"}}},
		{Standing: &one},
	}}))
	if _, err := e.agents.Prioritize(context.Background(), e.customer); err != nil {
		t.Fatal(err)
	}
	history := func(id string) findingHistory {
		return decode[findingHistory](t, e.do(httptest.NewRequest(http.MethodGet, "/findings/"+id+"/history", nil)), http.StatusOK)
	}

	second := history(f2).Entries
	if len(second) != 2 || second[1].Kind != "placed" || second[1].GroupBefore != nil || second[1].PrioritizationID != p.ID.String() {
		t.Fatalf("second's history = %+v, want placed, then placed again", second)
	}
	again := second[0]
	if again.Kind != "placed_again" || *again.GroupBefore != 2 || *again.GroupNow != 1 || again.Title != "Antes" || again.Reason != "Es el de pagos." ||
		!reflect.DeepEqual(again.Changes, []string{"feedback"}) || again.Band != nil || again.Score == nil || again.Score.From != again.Score.To {
		t.Errorf("second placed again = %+v", again)
	}
	if len(again.Feedback) != 1 || again.Feedback[0].Verdict != "should_be_earlier" || again.Feedback[0].Note != "es el de pagos" {
		t.Errorf("feedback = %+v", again.Feedback)
	}
	first := history(f1).Entries
	if len(first) != 2 || first[0].Kind != "moved" || !reflect.DeepEqual(first[0].GroupsAppeared, []string{"Antes"}) || first[0].Title != "Primero" ||
		first[0].Reason != "Va en pg-prod-01." || len(first[0].Evidence) != 1 || first[0].Evidence[0].Value != "pg-prod-01" ||
		first[0].Changes == nil || len(first[0].Changes) != 0 || first[0].Score != nil || first[0].CloseReason != nil {
		t.Errorf("first's history = %+v, want it moved under Antes with its reason", first)
	}
}

func TestFindingHistoryRefusesAFindingTheCallerCannotSee(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.prioritize(t)
	other := e
	other.customer = e.newCustomer(t)
	theirs := other.storeFindings(t)[0]
	platform := "Bearer " + e.signIn(t, e.newUser(t, tenancy.PlatformAdmin, tenancy.CustomerID{}))
	tests := []struct {
		name string
		rec  *httptest.ResponseRecorder
		want int
		code string
	}{
		{"another Customer's Finding", e.do(httptest.NewRequest(http.MethodGet, "/findings/"+theirs+"/history", nil)), http.StatusNotFound, "finding_not_found"},
		{"an unknown Finding", e.do(httptest.NewRequest(http.MethodGet, "/findings/"+uuid.NewString()+"/history", nil)), http.StatusNotFound, "finding_not_found"},
		{"an id that is not one", e.do(httptest.NewRequest(http.MethodGet, "/findings/nope/history", nil)), http.StatusBadRequest, "invalid_request"},
		{"a Platform Admin", e.as(platform, httptest.NewRequest(http.MethodGet, "/findings/"+theirs+"/history", nil)), http.StatusForbidden, "forbidden"},
	}
	for _, tt := range tests {
		if tt.rec.Code != tt.want || !strings.Contains(tt.rec.Body.String(), `"code":"`+tt.code+`"`) {
			t.Errorf("%s = %d %s, want %d %s", tt.name, tt.rec.Code, tt.rec.Body, tt.want, tt.code)
		}
	}
}
