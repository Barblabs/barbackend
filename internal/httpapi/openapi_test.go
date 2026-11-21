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

	templated := []struct{ method, path string }{
		{http.MethodGet, "/prioritizations/{id}"},
		{http.MethodPost, "/prioritizations/{id}/plans"},
		{http.MethodPost, "/prioritizations/{id}/feedback"},
		{http.MethodPost, "/findings/{id}/close"},
		{http.MethodPost, "/findings/{id}/reopen"},
		{http.MethodGet, "/findings/{id}/history"},
		{http.MethodPost, "/analista/conversations"},
		{http.MethodPost, "/analista/conversations/{id}/messages"},
		{http.MethodPut, "/areas/{id}/owner"},
		{http.MethodPut, "/assets/{id}/exposure"},
		{http.MethodDelete, "/assets/{id}/exposure"},
		{http.MethodPut, "/assets/{id}/information-classification"},
		{http.MethodDelete, "/assets/{id}/information-classification"},
	}
	for _, r := range slices.Concat(operations, businessContextEdits, everyRoleOperations, templated) {
		if op, ok := spec.Paths[r.path][strings.ToLower(r.method)]; !ok || op.OperationID == "" {
			t.Errorf("spec lacks %s %s with an operationId", r.method, r.path)
		}
	}
}

func TestOpenAPIListsTheLifecycleStageFilterValues(t *testing.T) {
	t.Parallel()
	rec := newEnv(t).send(httptest.NewRequest(http.MethodGet, "/openapi.json", nil))

	spec := decode[struct {
		Paths map[string]map[string]struct {
			Parameters []struct {
				Name   string `json:"name"`
				In     string `json:"in"`
				Schema struct {
					Items struct {
						Enum []string `json:"enum"`
					} `json:"items"`
				} `json:"schema"`
			} `json:"parameters"`
		} `json:"paths"`
	}](t, rec, http.StatusOK)

	for _, p := range spec.Paths["/assets"]["get"].Parameters {
		if p.Name == "lifecycle_stage" && p.In == "query" {
			if want := []string{"production", "implementation", "stock", "unknown"}; !slices.Equal(p.Schema.Items.Enum, want) {
				t.Errorf("lifecycle_stage enum = %v, want %v", p.Schema.Items.Enum, want)
			}
			return
		}
	}
	t.Error("GET /assets lacks the lifecycle_stage query parameter")
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
