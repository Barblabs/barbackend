package httpapi_test

import (
	"net/http"
	"net/http/httptest"
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

	routes := []struct{ method, path string }{
		{http.MethodGet, "/cmdb/source"},
		{http.MethodPost, "/cmdb/source"},
		{http.MethodPut, "/cmdb/source"},
		{http.MethodDelete, "/cmdb/source"},
		{http.MethodPost, "/cmdb/source/test"},
		{http.MethodPost, "/cmdb/source/sync"},
		{http.MethodGet, "/assets"},
	}
	for _, r := range routes {
		if op, ok := spec.Paths[r.path][strings.ToLower(r.method)]; !ok || op.OperationID == "" {
			t.Errorf("spec lacks %s %s with an operationId", r.method, r.path)
		}
	}
}
