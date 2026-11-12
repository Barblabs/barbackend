package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"barbackend/internal/claude/claudetest"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

func TestPrioritizationLifecycle(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	id := p.ID.String()
	f1, f2 := firstAndSecond(p)

	list := decode[struct {
		Prioritizations []struct {
			ID       string `json:"id"`
			Findings int    `json:"findings"`
			Groups   int    `json:"groups"`
		} `json:"prioritizations"`
	}](t, e.do(httptest.NewRequest(http.MethodGet, "/prioritizations", nil)), http.StatusOK)
	if len(list.Prioritizations) != 1 || list.Prioritizations[0].ID != id || list.Prioritizations[0].Findings != 2 || list.Prioritizations[0].Groups != 2 {
		t.Errorf("list = %+v", list)
	}

	got := decode[prioritizationBody](t, e.do(httptest.NewRequest(http.MethodGet, "/prioritizations/"+id, nil)), http.StatusOK)
	if got.ID != id || got.Model != "claude-haiku-5-5" || len(got.Groups) != 2 || got.Groups[0].Position != 1 || got.Groups[0].FindingIDs[0] != f1 || got.Groups[0].Evidence[0].Path != "/asset/name" {
		t.Errorf("prioritization = %+v", got)
	}
	if got.PreviousID != nil || got.BusinessContextVersion != nil {
		t.Errorf("previous = %v, business context = %v, want a first one, without a Business Context", got.PreviousID, got.BusinessContextVersion)
	}
	i := slices.IndexFunc(got.Findings, func(f findingBody) bool { return f.FindingID == f1 })
	if i < 0 {
		t.Fatalf("findings = %+v, want %s", got.Findings, f1)
	}
	first := got.Findings[i]
	if first.Group != 1 || first.ScoreRank != 2 || first.CVEID != "CVE-2025-1094" || first.PlacedAt == "" || first.ClosedAt != nil {
		t.Errorf("finding = %+v, want it in the first group though second by Score, open", first)
	}
	details := first.Details
	if details.Description != "PostgreSQL is affected." || details.Asset.Name != "pg-prod-01" || details.Asset.Criticality != "high" || details.ScoreDetails.Value != 0.3 {
		t.Errorf("details = %+v", details)
	}
	if details.KEV == nil || details.KEV.DateAdded != "2025-02-13" || details.Labeling.Outcome != "not_tried" {
		t.Errorf("details = %+v, want its KEV listing and no Labeling yet", details)
	}
	if details.Techniques == nil || details.Advisories == nil || details.Asset.CriticalServices == nil || details.ScoreDetails.DataGaps == nil {
		t.Errorf("details = %+v, want empty lists, never null", details)
	}

	e.llm.Queue(lunaReply(t))
	plan := decode[struct {
		FindingID string `json:"finding_id"`
		Output    struct {
			Steps []string `json:"steps"`
		} `json:"output"`
	}](t, e.do(jsonRequest(t, http.MethodPost, "/prioritizations/"+id+"/plans", map[string]string{"finding_id": f1})), http.StatusCreated)
	if plan.FindingID != f1 || len(plan.Output.Steps) != 1 {
		t.Errorf("plan = %+v", plan)
	}

	feedback := jsonRequest(t, http.MethodPost, "/prioritizations/"+id+"/feedback", map[string]string{"finding_id": f2, "verdict": "should_be_earlier", "note": "es el de pagos"})
	if rec := e.do(feedback); rec.Code != http.StatusCreated {
		t.Fatalf("feedback = %d %s", rec.Code, rec.Body)
	}

	got = decode[prioritizationBody](t, e.do(httptest.NewRequest(http.MethodGet, "/prioritizations/"+id, nil)), http.StatusOK)
	if len(got.Plans) != 1 || got.Plans[0].FindingID != f1 {
		t.Errorf("plans = %+v", got.Plans)
	}
	if len(got.Feedback) != 1 || got.Feedback[0].FindingID != f2 || got.Feedback[0].Verdict != "should_be_earlier" || got.Feedback[0].ViaAnalista {
		t.Errorf("feedback = %+v", got.Feedback)
	}
}

func TestPrioritizationErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	id := p.ID.String()
	f1, _ := firstAndSecond(p)
	calls := len(e.llm.Requests())
	missing := uuid.NewString()
	tests := []struct {
		name string
		req  *http.Request
		want int
		code string
	}{
		{"unknown Prioritization", httptest.NewRequest(http.MethodGet, "/prioritizations/"+missing, nil), http.StatusNotFound, "prioritization_not_found"},
		{"plan on an unknown Prioritization", jsonRequest(t, http.MethodPost, "/prioritizations/"+missing+"/plans", map[string]string{"finding_id": f1}), http.StatusNotFound, "prioritization_not_found"},
		{"plan for a Finding it does not hold", jsonRequest(t, http.MethodPost, "/prioritizations/"+id+"/plans", map[string]string{"finding_id": missing}), http.StatusNotFound, "finding_not_found"},
		{"plan for what is not a Finding's id", jsonRequest(t, http.MethodPost, "/prioritizations/"+id+"/plans", map[string]string{"finding_id": "f-9"}), http.StatusNotFound, "finding_not_found"},
		{"plan without a Finding", jsonRequest(t, http.MethodPost, "/prioritizations/"+id+"/plans", map[string]string{"finding_id": ""}), http.StatusBadRequest, "invalid_request"},
		{"feedback on a Finding it does not hold", jsonRequest(t, http.MethodPost, "/prioritizations/"+id+"/feedback", map[string]string{"finding_id": missing, "verdict": "applies"}), http.StatusNotFound, "finding_not_found"},
		{"feedback on an unknown Prioritization", jsonRequest(t, http.MethodPost, "/prioritizations/"+missing+"/feedback", map[string]string{"finding_id": f1, "verdict": "applies"}), http.StatusNotFound, "prioritization_not_found"},
		{"unknown verdict", jsonRequest(t, http.MethodPost, "/prioritizations/"+id+"/feedback", map[string]string{"finding_id": f1, "verdict": "maybe"}), http.StatusBadRequest, "invalid_request"},
		{"too long a note", jsonRequest(t, http.MethodPost, "/prioritizations/"+id+"/feedback", map[string]string{"finding_id": f1, "verdict": "applies", "note": strings.Repeat("x", 2001)}), http.StatusBadRequest, "invalid_request"},
		{"id that is not one", httptest.NewRequest(http.MethodGet, "/prioritizations/nope", nil), http.StatusBadRequest, "invalid_request"},
		{"blank message to the Analista", jsonRequest(t, http.MethodPost, "/analista/conversations", map[string]string{"message": "  "}), http.StatusBadRequest, "invalid_request"},
		{"unknown conversation", jsonRequest(t, http.MethodPost, "/analista/conversations/"+missing+"/messages", map[string]string{"message": "hola"}), http.StatusNotFound, "conversation_not_found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := e.do(tt.req)
			if rec.Code != tt.want || !strings.Contains(rec.Body.String(), `"code":"`+tt.code+`"`) {
				t.Errorf("= %d %s, want %d %s", rec.Code, rec.Body, tt.want, tt.code)
			}
		})
	}
	if len(e.llm.Requests()) != calls {
		t.Error("the model was called")
	}
}

func TestAnotherCustomerCannotReachAPrioritization(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	id := p.ID.String()
	f1, _ := firstAndSecond(p)
	stranger := "Bearer " + e.signIn(t, e.newUser(t, tenancy.Viewer, e.newCustomer(t)))

	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/prioritizations/"+id, nil),
		jsonRequest(t, http.MethodPost, "/prioritizations/"+id+"/plans", map[string]string{"finding_id": f1}),
		jsonRequest(t, http.MethodPost, "/prioritizations/"+id+"/feedback", map[string]string{"finding_id": f1, "verdict": "applies"}),
	} {
		req.Header.Set("Authorization", stranger)
		if rec := e.do(req); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d %s, want 404", req.Method, req.URL.Path, rec.Code, rec.Body)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/prioritizations", nil)
	req.Header.Set("Authorization", stranger)
	if rec := e.do(req); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), id) {
		t.Errorf("another Customer's list = %d %s", rec.Code, rec.Body)
	}
}

func TestPlanAnswersBadGatewayWhenLunaHasNoVerifiedAnswer(t *testing.T) {
	t.Parallel()
	invented := claudetest.JSON(t, map[string]any{"summary": "Sube a 99.9.", "steps": []string{"Sube a 99.9."}, "fixed_version": nil, "mitigation": nil, "verification": "Revisa.", "sources": []string{}})
	tests := []struct {
		name    string
		replies []claudetest.Reply
		code    string
	}{
		{"refused", []claudetest.Reply{claudetest.Refusal()}, "agent_refused"},
		{"rejected twice", []claudetest.Reply{invented, invented}, "agent_rejected"},
		{"failed", []claudetest.Reply{claudetest.Fail(http.StatusUnauthorized)}, "agent_unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			p := e.prioritize(t)
			id := p.ID.String()
			f1, _ := firstAndSecond(p)
			e.llm.Queue(tt.replies...)

			rec := e.do(jsonRequest(t, http.MethodPost, "/prioritizations/"+id+"/plans", map[string]string{"finding_id": f1}))

			if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), `"code":"`+tt.code+`"`) {
				t.Errorf("= %d %s, want 502 %s", rec.Code, rec.Body, tt.code)
			}
			for _, leaked := range []string{"claudetest", "99.9"} {
				if strings.Contains(rec.Body.String(), leaked) {
					t.Errorf("the model's text reached the client: %s", rec.Body)
				}
			}
		})
	}
}

func TestPlatformAdminIsForbiddenFromTheAgents(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	admin := "Bearer " + e.signIn(t, e.newUser(t, tenancy.PlatformAdmin, tenancy.CustomerID{}))
	id, f1 := uuid.NewString(), uuid.NewString()
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/prioritizations/"+id, nil),
		jsonRequest(t, http.MethodPost, "/prioritizations/"+id+"/plans", map[string]string{"finding_id": f1}),
		jsonRequest(t, http.MethodPost, "/prioritizations/"+id+"/feedback", map[string]string{"finding_id": f1, "verdict": "applies"}),
		jsonRequest(t, http.MethodPost, "/analista/conversations", map[string]string{"message": "hola"}),
		jsonRequest(t, http.MethodPost, "/analista/conversations/"+id+"/messages", map[string]string{"message": "hola"}),
	} {
		req.Header.Set("Authorization", admin)
		rec := e.do(req)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"forbidden"`) {
			t.Errorf("%s %s = %d %s, want 403 forbidden", req.Method, req.URL.Path, rec.Code, rec.Body)
		}
	}
	if len(e.llm.Requests()) != 0 {
		t.Error("the model was called")
	}
}

func TestAnalistaConversation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.llm.Queue(claudetest.Text("hola, ¿en qué te ayudo?"), claudetest.Text("sigues sin hallazgos"))
	type answer struct {
		ConversationID string `json:"conversation_id"`
		Reply          string `json:"reply"`
	}

	first := decode[answer](t, e.do(jsonRequest(t, http.MethodPost, "/analista/conversations", map[string]string{"message": "hola"})), http.StatusCreated)
	second := decode[answer](t, e.do(jsonRequest(t, http.MethodPost, "/analista/conversations/"+first.ConversationID+"/messages", map[string]string{"message": "¿y ahora?"})), http.StatusOK)

	if first.Reply != "hola, ¿en qué te ayudo?" || second.Reply != "sigues sin hallazgos" || second.ConversationID != first.ConversationID {
		t.Errorf("answers = %+v and %+v", first, second)
	}

	stranger := e.signIn(t, e.newUser(t, tenancy.Viewer, e.customer))
	req := jsonRequest(t, http.MethodPost, "/analista/conversations/"+first.ConversationID+"/messages", map[string]string{"message": "hola"})
	req.Header.Set("Authorization", "Bearer "+stranger)
	if rec := e.do(req); rec.Code != http.StatusNotFound {
		t.Errorf("another User's conversation = %d %s, want 404", rec.Code, rec.Body)
	}
}

func TestAnalistaFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		reply claudetest.Reply
		code  string
	}{
		{"refused", claudetest.Refusal(), "agent_refused"},
		{"unavailable", claudetest.Fail(http.StatusUnauthorized), "agent_unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.llm.Queue(tt.reply)
			rec := e.do(jsonRequest(t, http.MethodPost, "/analista/conversations", map[string]string{"message": "hola"}))
			if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), `"code":"`+tt.code+`"`) {
				t.Errorf("= %d %s, want 502 %s", rec.Code, rec.Body, tt.code)
			}
			if strings.Contains(rec.Body.String(), "claudetest") {
				t.Errorf("the model's error reached the client: %s", rec.Body)
			}
		})
	}
}
