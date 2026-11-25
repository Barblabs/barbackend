package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestCriticalServicesWithoutABusinessContextAreNoneForEveryCustomerRole(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for role, authorization := range map[string]string{"Viewer": "Bearer " + e.token, "Customer Admin": e.adminToken(t)} {
		got := decode[map[string]any](t, e.as(authorization, httptest.NewRequest(http.MethodGet, "/critical-services", nil)), http.StatusOK)

		if want := map[string]any{"critical_services": []any{}}; !reflect.DeepEqual(got, want) {
			t.Errorf("critical services as a %s = %v, want %v", role, got, want)
		}
	}
}

func TestCriticalServicesReportTheSavedServicesOnTheFindingsOfTheirAssets(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.storeFindings(t)
	_, admin := e.customerAdmin(t, e.customer)
	fields := contextFields("Zapatos.")
	fields["operations"].(map[string]any)["critical_services"] = []map[string]any{
		{"name": "Base de datos", "description": "", "impact": "high", "max_downtime": "4h_24h", "assets": []string{"PG-PROD-01", "web-01"}},
	}
	decode[businessContextBody](t, e.asUser(admin, http.MethodPut, "/business-context", map[string]any{"version": 0, "context": fields}), http.StatusOK)

	got := decode[map[string]any](t, e.do(httptest.NewRequest(http.MethodGet, "/critical-services", nil)), http.StatusOK)

	want := map[string]any{"critical_services": []any{map[string]any{
		"name": "Base de datos", "status": "clear", "critical_open": 0.0, "high_open": 1.0,
		"in_the_news": 0.0, "oldest_critical_days": nil, "unmatched_assets": []any{"web-01"},
	}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("critical services = %v, want %v", got, want)
	}
}

func TestCriticalServicesOfABusinessContextThatStatesNoneAreNone(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.storeFindings(t)
	_, admin := e.customerAdmin(t, e.customer)
	fields := contextFields("Zapatos.")
	fields["operations"].(map[string]any)["critical_services"] = []map[string]any{}
	decode[businessContextBody](t, e.asUser(admin, http.MethodPut, "/business-context", map[string]any{"version": 0, "context": fields}), http.StatusOK)

	got := decode[map[string]any](t, e.do(httptest.NewRequest(http.MethodGet, "/critical-services", nil)), http.StatusOK)

	if want := map[string]any{"critical_services": []any{}}; !reflect.DeepEqual(got, want) {
		t.Errorf("critical services = %v, want %v", got, want)
	}
}
