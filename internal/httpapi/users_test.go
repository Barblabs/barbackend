package httpapi_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

type user struct {
	ID         string     `json:"id"`
	Email      string     `json:"email"`
	Role       string     `json:"role"`
	CreatedAt  time.Time  `json:"created_at"`
	DisabledAt *time.Time `json:"disabled_at"`
}

// customerAdmin stores a Customer Admin of customer and returns their id and
// Authorization header.
func (e env) customerAdmin(t *testing.T, customer tenancy.CustomerID) (string, string) {
	t.Helper()
	sub := e.newUser(t, tenancy.CustomerAdmin, customer)
	return e.userID(t, sub), "Bearer " + e.signIn(t, sub)
}

func (e env) userID(t *testing.T, sub string) string {
	t.Helper()
	var u tenancy.User
	if err := e.db.InTx(context.Background(), func(tx *postgres.Tx) (err error) {
		u, err = tx.UserBySub(context.Background(), sub)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return u.ID().String()
}

func TestOnlyACustomerAdminManagesUsers(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, role := range []tenancy.Role{tenancy.Viewer, tenancy.PlatformAdmin} {
		customer := e.customer
		if role == tenancy.PlatformAdmin {
			customer = tenancy.CustomerID{}
		}
		token := "Bearer " + e.signIn(t, e.newUser(t, role, customer))
		for _, op := range customerAdminOperations {
			rec := e.asUser(token, op.method, op.path, map[string]string{"email": "a@example.com", "role": "viewer"})

			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"forbidden"`) {
				t.Errorf("%s: %s %s = %d %s, want 403 forbidden", role, op.method, op.path, rec.Code, rec.Body)
			}
		}
	}
	if invited := e.admin.invited(); len(invited) != 0 {
		t.Errorf("invited %v, want nobody", invited)
	}
}

func TestCustomerAdminInvitesPromotesAndDisablesAUser(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_, admin := e.customerAdmin(t, e.customer)

	invited := decode[user](t, e.asUser(admin, http.MethodPost, "/users", map[string]string{"email": "Ana@Example.com", "role": "viewer"}), http.StatusCreated)
	anaSub := e.admin.invited()[0]
	ana := "Bearer " + e.signIn(t, anaSub)
	if invited.Email != "ana@example.com" || invited.Role != "viewer" || invited.DisabledAt != nil {
		t.Errorf("invited = %+v, want an enabled viewer ana@example.com", invited)
	}

	promoted := decode[user](t, e.asUser(admin, http.MethodPatch, "/users/"+invited.ID, map[string]string{"role": "customer_admin"}), http.StatusOK)
	if promoted.Role != "customer_admin" {
		t.Errorf("role after promoting = %q, want customer_admin", promoted.Role)
	}
	if code := e.asUser(ana, http.MethodGet, "/users", nil).Code; code != http.StatusOK {
		t.Errorf("list as the promoted User = %d, want 200", code)
	}

	disabled := decode[user](t, e.asUser(admin, http.MethodPost, "/users/"+invited.ID+"/disable", nil), http.StatusOK)
	if disabled.DisabledAt == nil {
		t.Error("disabled_at = null after disabling")
	}
	if code := e.asUser(ana, http.MethodGet, "/users", nil).Code; code != http.StatusUnauthorized {
		t.Errorf("list as the disabled User = %d, want 401", code)
	}
}

func TestCustomerAdminSeesOnlyTheUsersOfTheirCustomer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	adminID, admin := e.customerAdmin(t, e.customer)
	otherID, _ := e.customerAdmin(t, e.newCustomer(t))

	got := decode[struct {
		Users []user `json:"users"`
	}](t, e.asUser(admin, http.MethodGet, "/users", nil), http.StatusOK)
	ids := make([]string, 0, len(got.Users))
	for _, u := range got.Users {
		ids = append(ids, u.ID)
	}
	if len(ids) != 2 || !slices.Contains(ids, adminID) || slices.Contains(ids, otherID) {
		t.Errorf("listed %v, want the env's Viewer and %s, not %s", ids, adminID, otherID)
	}

	for _, op := range []struct {
		method, path string
		body         map[string]string
	}{
		{http.MethodPatch, "/users/" + otherID, map[string]string{"role": "viewer"}},
		{http.MethodPost, "/users/" + otherID + "/disable", nil},
	} {
		rec := e.asUser(admin, op.method, op.path, op.body)

		if got := decode[codedError](t, rec, http.StatusNotFound); got.Code != "user_not_found" {
			t.Errorf("%s %s: code = %q, want user_not_found", op.method, op.path, got.Code)
		}
	}
}

func TestTheLastCustomerAdminCannotBeRemoved(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id, admin := e.customerAdmin(t, e.customer)
	for _, op := range []struct {
		method, path string
		body         map[string]string
	}{
		{http.MethodPatch, "/users/" + id, map[string]string{"role": "viewer"}},
		{http.MethodPost, "/users/" + id + "/disable", nil},
	} {
		rec := e.asUser(admin, op.method, op.path, op.body)

		if got := decode[codedError](t, rec, http.StatusConflict); got.Code != "last_customer_admin" {
			t.Errorf("%s %s: code = %q, want last_customer_admin", op.method, op.path, got.Code)
		}
	}
}

func TestTwoCustomerAdminsDemotingEachOtherAtOnceKeepOne(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	aID, a := e.customerAdmin(t, e.customer)
	bID, b := e.customerAdmin(t, e.customer)
	holder := pgtest.LockCustomer(t, e.conn, e.customer)

	codes := make(chan int, 2)
	demote := func(caller, id string) {
		codes <- e.asUser(caller, http.MethodPatch, "/users/"+id, map[string]string{"role": "viewer"}).Code
	}
	go demote(a, bID)
	go demote(b, aID)
	pgtest.WaitForLockWaiters(t, e.conn, 2)
	if err := holder.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}

	got := []int{<-codes, <-codes}
	slices.Sort(got)
	if got[0] != http.StatusOK || got[1] != http.StatusConflict {
		t.Errorf("statuses = %v, want one 200 and one 409", got)
	}
}

func TestUserManagementErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id, admin := e.customerAdmin(t, e.customer)
	decode[user](t, e.asUser(admin, http.MethodPost, "/users", map[string]string{"email": "a@example.com", "role": "viewer"}), http.StatusCreated)
	tests := []struct {
		name         string
		method, path string
		body         map[string]string
		status       int
		code         string
	}{
		{"taken email", http.MethodPost, "/users", map[string]string{"email": "A@example.com", "role": "viewer"}, http.StatusConflict, "email_taken"},
		{"malformed email", http.MethodPost, "/users", map[string]string{"email": "not-an-email", "role": "viewer"}, http.StatusBadRequest, "invalid_request"},
		{"invite a platform admin", http.MethodPost, "/users", map[string]string{"email": "b@example.com", "role": "platform_admin"}, http.StatusBadRequest, "invalid_request"},
		{"make a platform admin", http.MethodPatch, "/users/" + id, map[string]string{"role": "platform_admin"}, http.StatusBadRequest, "invalid_request"},
		{"change an unknown user", http.MethodPatch, "/users/" + uuid.NewString(), map[string]string{"role": "viewer"}, http.StatusNotFound, "user_not_found"},
		{"disable a malformed id", http.MethodPost, "/users/not-a-uuid/disable", nil, http.StatusBadRequest, "invalid_request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := e.asUser(admin, tt.method, tt.path, tt.body)

			if got := decode[codedError](t, rec, tt.status); got.Code != tt.code {
				t.Errorf("code = %q, want %q", got.Code, tt.code)
			}
		})
	}
}
