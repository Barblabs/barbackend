package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

type customer struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	CreatedAt     time.Time  `json:"created_at"`
	DeactivatedAt *time.Time `json:"deactivated_at"`
}

func (e env) platformAdmin(t *testing.T) string {
	t.Helper()
	return "Bearer " + e.signIn(t, e.newUser(t, tenancy.PlatformAdmin, tenancy.CustomerID{}))
}

func (e env) asUser(authorization, method, path string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
	req.Header.Set("Authorization", authorization)
	return e.send(req)
}

func TestUsersOfACustomerCannotManageCustomers(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, role := range []tenancy.Role{tenancy.CustomerAdmin, tenancy.Viewer} {
		token := "Bearer " + e.signIn(t, e.newUser(t, role, e.customer))
		for _, op := range platformOperations {
			rec := e.asUser(token, op.method, op.path, map[string]string{"name": "Acme", "admin_email": "a@example.com"})

			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"forbidden"`) {
				t.Errorf("%s: %s %s = %d %s, want 403 forbidden", role, op.method, op.path, rec.Code, rec.Body)
			}
		}
	}
	if invited := e.admin.invited(); len(invited) != 0 {
		t.Errorf("invited %v, want nobody", invited)
	}
}

func TestDeactivatedCustomerLosesAccessAndSyncUntilReactivated(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	staff := e.platformAdmin(t)
	created := decode[customer](t, e.asUser(staff, http.MethodPost, "/customers", map[string]string{"name": "Acme", "admin_email": "ana@example.com"}), http.StatusCreated)
	id := tenancy.CustomerID(uuid.MustParse(created.ID))
	e.connect(t, id)
	ana := "Bearer " + e.signIn(t, e.admin.invited()[0])
	syncAsAna := func() int { return e.asUser(ana, http.MethodPost, "/cmdb/source/sync", nil).Code }
	if code := syncAsAna(); code != http.StatusOK {
		t.Fatalf("sync before deactivating = %d, want 200", code)
	}

	deactivated := decode[customer](t, e.asUser(staff, http.MethodPost, "/customers/"+created.ID+"/deactivate", nil), http.StatusOK)

	if deactivated.DeactivatedAt == nil {
		t.Error("deactivated_at = null after deactivating")
	}
	if code := syncAsAna(); code != http.StatusForbidden {
		t.Errorf("sync as its admin after deactivating = %d, want 403", code)
	}
	if _, err := e.cmdb.SyncConnected(context.Background(), viewerOf(id)); !errors.Is(err, tenancy.ErrCustomerDeactivated) {
		t.Errorf("sync after deactivating: err = %v, want ErrCustomerDeactivated", err)
	}

	decode[customer](t, e.asUser(staff, http.MethodPost, "/customers/"+created.ID+"/reactivate", nil), http.StatusOK)

	if code := syncAsAna(); code != http.StatusOK {
		t.Errorf("sync as its admin after reactivating = %d, want 200", code)
	}
}

func TestListCustomersOrdersThemByName(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	staff := e.platformAdmin(t)
	for _, name := range []string{"globex", "Acme"} {
		decode[customer](t, e.asUser(staff, http.MethodPost, "/customers", map[string]string{"name": name, "admin_email": name + "@example.com"}), http.StatusCreated)
	}

	got := decode[struct {
		Customers []customer `json:"customers"`
	}](t, e.asUser(staff, http.MethodGet, "/customers", nil), http.StatusOK)

	// The env's own Customer is named by its id, a lowercase hex uuid.
	var names []string
	for _, c := range got.Customers {
		if c.ID != e.customer.String() {
			names = append(names, c.Name)
		}
	}
	if strings.Join(names, ",") != "Acme,globex" {
		t.Errorf("names = %v, want Acme, globex", names)
	}
}

func TestCustomerManagementErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	staff := e.platformAdmin(t)
	decode[customer](t, e.asUser(staff, http.MethodPost, "/customers", map[string]string{"name": "Acme", "admin_email": "a@example.com"}), http.StatusCreated)
	globex := decode[customer](t, e.asUser(staff, http.MethodPost, "/customers", map[string]string{"name": "Globex", "admin_email": "g@example.com"}), http.StatusCreated)
	tests := []struct {
		name         string
		method, path string
		body         map[string]string
		status       int
		code         string
	}{
		{"taken name", http.MethodPost, "/customers", map[string]string{"name": " ACME ", "admin_email": "b@example.com"}, http.StatusConflict, "customer_name_taken"},
		{"taken email", http.MethodPost, "/customers", map[string]string{"name": "Initech", "admin_email": "A@example.com"}, http.StatusConflict, "email_taken"},
		{"blank name", http.MethodPost, "/customers", map[string]string{"name": "  ", "admin_email": "b@example.com"}, http.StatusBadRequest, "invalid_request"},
		{"malformed email", http.MethodPost, "/customers", map[string]string{"name": "Initech", "admin_email": "not-an-email"}, http.StatusBadRequest, "invalid_request"},
		{"rename to a taken name", http.MethodPatch, "/customers/" + globex.ID, map[string]string{"name": "acme"}, http.StatusConflict, "customer_name_taken"},
		{"rename a malformed id", http.MethodPatch, "/customers/not-a-uuid", map[string]string{"name": "Initech"}, http.StatusBadRequest, "invalid_request"},
		{"rename an unknown customer", http.MethodPatch, "/customers/" + uuid.NewString(), map[string]string{"name": "Initech"}, http.StatusNotFound, "customer_not_found"},
		{"deactivate an unknown customer", http.MethodPost, "/customers/" + uuid.NewString() + "/deactivate", nil, http.StatusNotFound, "customer_not_found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := e.asUser(staff, tt.method, tt.path, tt.body)

			if got := decode[codedError](t, rec, tt.status); got.Code != tt.code {
				t.Errorf("code = %q, want %q", got.Code, tt.code)
			}
		})
	}
}

func TestPlatformAdminSeesTheStatsOfEveryCustomer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.connect(t, e.customer)
	other := e.newCustomer(t)

	got := decode[struct {
		Customers []struct {
			ID                   string     `json:"id"`
			Active               bool       `json:"active"`
			UserCount            int        `json:"user_count"`
			CMDBConnected        bool       `json:"cmdb_connected"`
			CMDBLastSync         *time.Time `json:"cmdb_last_sync"`
			CMDBLastSyncFailedAt *time.Time `json:"cmdb_last_sync_failed_at"`
		} `json:"customers"`
	}](t, e.asUser(e.platformAdmin(t), http.MethodGet, "/customers/stats", nil), http.StatusOK)

	byID := map[string]int{}
	for i, c := range got.Customers {
		byID[c.ID] = i
	}
	connected, ok := byID[e.customer.String()]
	empty, okOther := byID[other.String()]
	if len(got.Customers) != 2 || !ok || !okOther {
		t.Fatalf("customers = %+v, want the env's Customer and the other one", got.Customers)
	}
	if c := got.Customers[connected]; !c.Active || c.UserCount != 1 || !c.CMDBConnected || c.CMDBLastSync == nil || c.CMDBLastSyncFailedAt != nil {
		t.Errorf("connected Customer = %+v, want active, 1 User, connected and synced", c)
	}
	if c := got.Customers[empty]; !c.Active || c.UserCount != 0 || c.CMDBConnected || c.CMDBLastSync != nil {
		t.Errorf("other Customer = %+v, want active, no Users and no CMDB Source", c)
	}
}

func TestPlatformAdminSeesSyncHealthAndSlackDeliveries(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	staff := e.platformAdmin(t)

	health := decode[struct {
		Days []struct {
			Date      string `json:"date"`
			Succeeded int    `json:"succeeded"`
		} `json:"days"`
	}](t, e.asUser(staff, http.MethodGet, "/customers/sync-health?days=7", nil), http.StatusOK)
	deliveries := decode[struct {
		Customers []struct {
			ID   string `json:"id"`
			Sent int    `json:"sent"`
		} `json:"customers"`
	}](t, e.asUser(staff, http.MethodGet, "/customers/slack-deliveries", nil), http.StatusOK)
	tooMany := e.asUser(staff, http.MethodGet, "/customers/sync-health?days=91", nil)

	if len(health.Days) != 7 || health.Days[6].Date != time.Now().UTC().Format(time.DateOnly) {
		t.Errorf("sync health = %+v, want 7 days ending today", health.Days)
	}
	if len(deliveries.Customers) != 1 || deliveries.Customers[0].ID != e.customer.String() || deliveries.Customers[0].Sent != 0 {
		t.Errorf("slack deliveries = %+v, want the env's Customer with nothing sent", deliveries.Customers)
	}
	if tooMany.Code != http.StatusBadRequest {
		t.Errorf("91 days = %d %s, want 400", tooMany.Code, tooMany.Body)
	}
}
