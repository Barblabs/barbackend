package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

type closedFindings struct {
	Findings []struct {
		ID        string  `json:"id"`
		CVEID     string  `json:"cve_id"`
		AssetName string  `json:"asset_name"`
		Reason    string  `json:"reason"`
		Note      string  `json:"note"`
		ClosedBy  string  `json:"closed_by"`
		ReopenAt  *string `json:"reopen_at"`
	} `json:"findings"`
}

func closeBody(reason, note string, reopenAt *time.Time) map[string]any {
	b := map[string]any{"reason": reason, "note": note}
	if reopenAt != nil {
		b["reopen_at"] = reopenAt.Format(time.RFC3339)
	}
	return b
}

func TestAViewerClosesListsAndReopensAFinding(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.storeFindings(t)[0]
	reopenAt := time.Now().Add(30 * 24 * time.Hour)

	if rec := e.do(jsonRequest(t, http.MethodPost, "/findings/"+id+"/close", closeBody("accepted_risk", "Behind the WAF.", &reopenAt))); rec.Code != http.StatusNoContent {
		t.Fatalf("close = %d %s, want 204", rec.Code, rec.Body)
	}
	got := decode[closedFindings](t, e.do(httptest.NewRequest(http.MethodGet, "/findings/closed", nil)), http.StatusOK)
	if len(got.Findings) != 1 {
		t.Fatalf("closed = %+v, want the one closed", got)
	}
	if f := got.Findings[0]; f.ID != id || f.CVEID != "CVE-2025-1094" || f.AssetName != "pg-prod-01" || f.Reason != "accepted_risk" ||
		f.Note != "Behind the WAF." || !strings.HasSuffix(f.ClosedBy, "@example.com") || f.ReopenAt == nil {
		t.Errorf("closed finding = %+v", f)
	}
	if rec := e.do(jsonRequest(t, http.MethodPost, "/findings/"+id+"/close", closeBody("false_positive", "Lab.", nil))); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"code":"finding_closed"`) {
		t.Errorf("second close = %d %s, want 409 finding_closed", rec.Code, rec.Body)
	}

	if rec := e.do(httptest.NewRequest(http.MethodPost, "/findings/"+id+"/reopen", nil)); rec.Code != http.StatusNoContent {
		t.Fatalf("reopen = %d %s, want 204", rec.Code, rec.Body)
	}
	if got := decode[closedFindings](t, e.do(httptest.NewRequest(http.MethodGet, "/findings/closed", nil)), http.StatusOK); len(got.Findings) != 0 {
		t.Errorf("closed after reopening = %+v, want none", got)
	}
	if rec := e.do(httptest.NewRequest(http.MethodPost, "/findings/"+id+"/reopen", nil)); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"code":"finding_not_closed_by_hand"`) {
		t.Errorf("reopen of an open Finding = %d %s, want 409 finding_not_closed_by_hand", rec.Code, rec.Body)
	}
}

func TestCloseFindingRefusesAnInvalidOrUnknownClose(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.storeFindings(t)[0]
	other := e
	other.customer = e.newCustomer(t)
	otherID := other.storeFindings(t)[0]
	path := "/findings/" + id + "/close"
	ahead, past := time.Now().Add(time.Hour), time.Now().Add(-time.Hour)
	tests := []struct {
		name string
		req  *http.Request
		want int
		code string
	}{
		{"a reason only a match gives", jsonRequest(t, http.MethodPost, path, closeBody("asset_inactive", "Gone.", nil)), http.StatusBadRequest, "invalid_request"},
		{"no note", jsonRequest(t, http.MethodPost, path, closeBody("false_positive", "", nil)), http.StatusBadRequest, "invalid_request"},
		{"a blank note", jsonRequest(t, http.MethodPost, path, closeBody("false_positive", "   ", nil)), http.StatusBadRequest, "invalid_request"},
		{"too long a note", jsonRequest(t, http.MethodPost, path, closeBody("false_positive", strings.Repeat("x", 2001), nil)), http.StatusBadRequest, "invalid_request"},
		{"postponed without reopen_at", jsonRequest(t, http.MethodPost, path, closeBody("postponed", "Next sprint.", nil)), http.StatusBadRequest, "invalid_request"},
		{"false_positive with reopen_at", jsonRequest(t, http.MethodPost, path, closeBody("false_positive", "Lab.", &ahead)), http.StatusBadRequest, "invalid_request"},
		{"reopen_at already past", jsonRequest(t, http.MethodPost, path, closeBody("postponed", "Later.", &past)), http.StatusBadRequest, "invalid_request"},
		{"an unknown Finding", jsonRequest(t, http.MethodPost, "/findings/"+uuid.NewString()+"/close", closeBody("false_positive", "Lab.", nil)), http.StatusNotFound, "finding_not_found"},
		{"another Customer's Finding", jsonRequest(t, http.MethodPost, "/findings/"+otherID+"/close", closeBody("false_positive", "Lab.", nil)), http.StatusNotFound, "finding_not_found"},
		{"reopen of an unknown Finding", httptest.NewRequest(http.MethodPost, "/findings/"+uuid.NewString()+"/reopen", nil), http.StatusNotFound, "finding_not_found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := e.do(tt.req)
			if rec.Code != tt.want || !strings.Contains(rec.Body.String(), `"code":"`+tt.code+`"`) {
				t.Errorf("= %d %s, want %d %s", rec.Code, rec.Body, tt.want, tt.code)
			}
		})
	}
	if got := decode[closedFindings](t, e.do(httptest.NewRequest(http.MethodGet, "/findings/closed", nil)), http.StatusOK); len(got.Findings) != 0 {
		t.Errorf("closed = %+v, want none", got)
	}
}

func TestACustomerAdminClosesAndAPlatformAdminCannot(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ids := e.storeFindings(t)
	platform := "Bearer " + e.signIn(t, e.newUser(t, tenancy.PlatformAdmin, tenancy.CustomerID{}))

	if rec := e.as(platform, jsonRequest(t, http.MethodPost, "/findings/"+ids[0]+"/close", closeBody("false_positive", "Lab.", nil))); rec.Code != http.StatusForbidden {
		t.Errorf("Platform Admin's close = %d %s, want 403", rec.Code, rec.Body)
	}
	if rec := e.as(platform, httptest.NewRequest(http.MethodPost, "/findings/"+ids[0]+"/reopen", nil)); rec.Code != http.StatusForbidden {
		t.Errorf("Platform Admin's reopen = %d %s, want 403", rec.Code, rec.Body)
	}
	if rec := e.as(e.adminToken(t), jsonRequest(t, http.MethodPost, "/findings/"+ids[1]+"/close", closeBody("remediated", "Patched to 17.2.", nil))); rec.Code != http.StatusNoContent {
		t.Errorf("Customer Admin's close = %d %s, want 204", rec.Code, rec.Body)
	}
}
