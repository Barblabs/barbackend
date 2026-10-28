package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestOpenAPIListsEveryRoute(t *testing.T) {
	t.Parallel()
	rec := newEnv(t).do(httptest.NewRequest(http.MethodGet, "/openapi.json", nil))

	spec := decode[struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
		} `json:"paths"`
	}](t, rec, http.StatusOK)

	for _, r := range slices.Concat(operations, everyRoleOperations) {
		if op, ok := spec.Paths[r.path][strings.ToLower(r.method)]; !ok || op.OperationID == "" {
			t.Errorf("spec lacks %s %s with an operationId", r.method, r.path)
		}
	}
}

func TestOpenAPIDeclaresBearerAuthentication(t *testing.T) {
	t.Parallel()
	rec := newEnv(t).send(httptest.NewRequest(http.MethodGet, "/openapi.json", nil))

	spec := decode[struct {
		Security   []map[string][]string `json:"security"`
		Components struct {
			SecuritySchemes map[string]struct {
				Type   string `json:"type"`
				Scheme string `json:"scheme"`
			} `json:"securitySchemes"`
		} `json:"components"`
	}](t, rec, http.StatusOK)

	if len(spec.Security) != 1 || spec.Security[0]["bearer"] == nil {
		t.Errorf("security = %v, want bearer on every operation", spec.Security)
	}
	if s := spec.Components.SecuritySchemes["bearer"]; s.Type != "http" || s.Scheme != "bearer" {
		t.Errorf("bearer scheme = %+v, want http bearer", s)
	}
}
