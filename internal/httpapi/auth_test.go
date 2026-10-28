package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"barbackend/internal/cognito/cognitotest"
	"barbackend/internal/tenancy"
)

func TestUnauthenticatedRequestsAreRejected(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	sub := e.newUser(t, tenancy.Viewer, e.customer)
	with := func(edit func(map[string]any)) string {
		claims := cognitotest.Claims(sub)
		edit(claims)
		return e.pool.Sign(t, claims)
	}
	disabled := e.newUser(t, tenancy.Viewer, e.customer)
	if _, err := e.conn.Exec(context.Background(), "UPDATE users SET disabled_at = now() WHERE cognito_sub = $1", disabled); err != nil {
		t.Fatal(err)
	}
	deactivated := e.newCustomer(t)
	ofDeactivated := e.newUser(t, tenancy.Viewer, deactivated)
	if _, err := e.conn.Exec(context.Background(), "UPDATE customers SET deactivated_at = now() WHERE id = $1", [16]byte(deactivated)); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		authorization string
	}{
		{"missing", ""},
		{"not bearer", "Basic " + e.signIn(t, sub)},
		{"malformed", "Bearer not-a-jwt"},
		{"expired", "Bearer " + with(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute) })},
		{"without expiry", "Bearer " + with(func(c map[string]any) { delete(c, "exp") })},
		{"wrongly signed", "Bearer " + cognitotest.SignWithOtherKey(t, cognitotest.Claims(sub))},
		{"wrong issuer", "Bearer " + with(func(c map[string]any) { c["iss"] = "https://cognito-idp.test/other-pool" })},
		{"wrong client", "Bearer " + with(func(c map[string]any) { c["client_id"] = "other-client" })},
		{"id token", "Bearer " + with(func(c map[string]any) { c["token_use"] = "id" })},
		{"unknown user", "Bearer " + e.signIn(t, "unknown-sub")},
		{"disabled user", "Bearer " + e.signIn(t, disabled)},
		{"user of a deactivated customer", "Bearer " + e.signIn(t, ofDeactivated)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, path := range []string{"/assets", "/me"} {
				req := httptest.NewRequest(http.MethodGet, path, nil)
				if tt.authorization != "" {
					req.Header.Set("Authorization", tt.authorization)
				}

				rec := e.send(req)

				if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"code":"unauthenticated"`) {
					t.Errorf("GET %s = %d %s, want 401 unauthenticated", path, rec.Code, rec.Body)
				}
				if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
					t.Errorf("GET %s WWW-Authenticate = %q, want Bearer", path, got)
				}
			}
		})
	}
}

func TestEveryOperationRequiresAToken(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, op := range slices.Concat(operations, platformOperations, customerAdminOperations, everyRoleOperations) {
		rec := e.send(httptest.NewRequest(op.method, op.path, loginBody()))

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d %s, want 401", op.method, op.path, rec.Code, rec.Body)
		}
	}
}

func TestPlatformAdminIsForbiddenFromCustomerEndpoints(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.connect(t, e.customer)
	admin := "Bearer " + e.signIn(t, e.newUser(t, tenancy.PlatformAdmin, tenancy.CustomerID{}))
	for _, op := range operations {
		req := httptest.NewRequest(op.method, op.path, loginBody())
		req.Header.Set("Authorization", admin)

		rec := e.do(req)

		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"forbidden"`) {
			t.Errorf("%s %s = %d %s, want 403 forbidden", op.method, op.path, rec.Code, rec.Body)
		}
	}
}

func TestOpenRoutesNeedNoToken(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, path := range []string{"/ping", "/openapi.json", "/openapi.yaml", "/docs"} {
		if rec := e.send(httptest.NewRequest(http.MethodGet, path, nil)); rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, rec.Code)
		}
	}
}

func loginBody() *strings.Reader {
	body, _ := json.Marshal(validLogin())
	return strings.NewReader(string(body))
}
