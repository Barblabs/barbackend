package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestCORS(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		origin     string
		wantStatus int
		wantOrigin string
	}{
		{"preflight from allowed origin", http.MethodOptions, allowedOrigin, http.StatusNoContent, allowedOrigin},
		{"preflight from other origin", http.MethodOptions, "http://evil.example", http.StatusForbidden, ""},
		{"request from allowed origin", http.MethodGet, allowedOrigin, http.StatusOK, allowedOrigin},
		{"request from other origin", http.MethodGet, "http://evil.example", http.StatusOK, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(tt.method, "/cmdb/source", nil)
			req.Header.Set("Origin", tt.origin)
			if tt.method == http.MethodOptions {
				req.Header.Set("Access-Control-Request-Method", http.MethodGet)
				req.Header.Set("Access-Control-Request-Headers", "content-type")
			}

			rec := newEnv(t).do(req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != tt.wantOrigin {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, tt.wantOrigin)
			}
			allowsMethods := rec.Header().Get("Access-Control-Allow-Methods") != ""
			if want := tt.wantStatus == http.StatusNoContent; allowsMethods != want {
				t.Errorf("Access-Control-Allow-Methods = %q, want set: %v", rec.Header().Get("Access-Control-Allow-Methods"), want)
			}
		})
	}
}

// PUT is not a CORS-safelisted method, so a browser sends it only once the
// preflight allows it.
func TestCORSPreflightAllowsPut(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodOptions, "/cmdb/source", nil)
	req.Header.Set("Origin", allowedOrigin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPut)

	rec := newEnv(t).do(req)

	if got := rec.Header().Get("Access-Control-Allow-Methods"); !slices.Contains(strings.Split(got, ", "), http.MethodPut) {
		t.Errorf("Access-Control-Allow-Methods = %q, want PUT", got)
	}
}
