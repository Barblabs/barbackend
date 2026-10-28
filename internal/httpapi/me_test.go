package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"barbackend/internal/tenancy"
)

type me struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Customer *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"customer"`
}

func TestMeAnswersTheCallersRoleAndCustomer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	tests := []struct {
		role         tenancy.Role
		customer     tenancy.CustomerID
		wantCode     string
		wantCustomer bool
	}{
		{tenancy.PlatformAdmin, tenancy.CustomerID{}, "platform_admin", false},
		{tenancy.CustomerAdmin, e.customer, "customer_admin", true},
		{tenancy.Viewer, e.customer, "viewer", true},
	}
	for _, tt := range tests {
		t.Run(tt.wantCode, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/me", nil)
			req.Header.Set("Authorization", "Bearer "+e.signIn(t, e.newUser(t, tt.role, tt.customer)))

			got := decode[me](t, e.do(req), http.StatusOK)

			if got.ID == "" || got.Email == "" || got.Role != tt.wantCode {
				t.Errorf("me = %+v, want an id, an email and role %s", got, tt.wantCode)
			}
			switch {
			case !tt.wantCustomer && got.Customer != nil:
				t.Errorf("customer = %+v, want null", *got.Customer)
			case tt.wantCustomer && (got.Customer == nil || got.Customer.ID != e.customer.String() || got.Customer.Name != e.customer.String()):
				t.Errorf("customer = %+v, want the env's Customer by id and name", got.Customer)
			}
		})
	}
}
