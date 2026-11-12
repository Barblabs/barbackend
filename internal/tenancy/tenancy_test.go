package tenancy_test

import (
	"errors"
	"testing"

	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

var (
	userID   = tenancy.UserID(uuid.New())
	customer = tenancy.CustomerID(uuid.New())
)

func TestNewUser(t *testing.T) {
	tests := []struct {
		name     string
		id       tenancy.UserID
		email    string
		role     tenancy.Role
		customer tenancy.CustomerID
		want     error
	}{
		{"viewer", userID, "a@example.com", tenancy.Viewer, customer, nil},
		{"customer admin", userID, "a@example.com", tenancy.CustomerAdmin, customer, nil},
		{"platform admin", userID, "a@example.com", tenancy.PlatformAdmin, tenancy.CustomerID{}, nil},
		{"zero id", tenancy.UserID{}, "a@example.com", tenancy.Viewer, customer, tenancy.ErrInvalidUser},
		{"blank email", userID, " \t", tenancy.Viewer, customer, tenancy.ErrInvalidUser},
		{"unknown role", userID, "a@example.com", tenancy.Role(4), customer, tenancy.ErrInvalidUser},
		{"zero role", userID, "a@example.com", tenancy.Role(0), customer, tenancy.ErrInvalidUser},
		{"platform admin with a customer", userID, "a@example.com", tenancy.PlatformAdmin, customer, tenancy.ErrInvalidUser},
		{"customer admin without a customer", userID, "a@example.com", tenancy.CustomerAdmin, tenancy.CustomerID{}, tenancy.ErrInvalidUser},
		{"viewer without a customer", userID, "a@example.com", tenancy.Viewer, tenancy.CustomerID{}, tenancy.ErrInvalidUser},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tenancy.NewUser(tt.id, tt.email, tt.role, tt.customer)
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestNewUserNormalizesEmail(t *testing.T) {
	u, err := tenancy.NewUser(userID, "  Ana@Example.COM\n", tenancy.Viewer, customer)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Email(); got != "ana@example.com" {
		t.Errorf("email = %q, want ana@example.com", got)
	}
}

func TestSignIn(t *testing.T) {
	tests := []struct {
		name  string
		state tenancy.UserState
		want  error
	}{
		{"active", tenancy.UserState{}, nil},
		{"disabled", tenancy.UserState{Disabled: true}, tenancy.ErrUserDisabled},
		{"deactivated customer", tenancy.UserState{CustomerDeactivated: true}, tenancy.ErrCustomerDeactivated},
		{"disabled in a deactivated customer", tenancy.UserState{Disabled: true, CustomerDeactivated: true}, tenancy.ErrUserDisabled},
		{"pending", tenancy.UserState{Pending: true}, tenancy.ErrUserPending},
		{"pending and disabled", tenancy.UserState{Pending: true, Disabled: true}, tenancy.ErrUserDisabled},
		{"pending in a deactivated customer", tenancy.UserState{Pending: true, CustomerDeactivated: true}, tenancy.ErrUserPending},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := tenancy.RestoreUser(userID, "a@example.com", tenancy.Viewer, customer, tt.state)
			if err != nil {
				t.Fatal(err)
			}
			if err := u.SignIn(); !errors.Is(err, tt.want) {
				t.Errorf("SignIn = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestActsFor(t *testing.T) {
	viewer, _ := tenancy.NewUser(userID, "a@example.com", tenancy.Viewer, customer)
	if got, err := viewer.ActsFor(); err != nil || got != customer {
		t.Errorf("viewer acts for %v, %v, want %v", got, err, customer)
	}
	admin, _ := tenancy.NewUser(userID, "a@example.com", tenancy.PlatformAdmin, tenancy.CustomerID{})
	if _, err := admin.ActsFor(); !errors.Is(err, tenancy.ErrNoCustomer) {
		t.Errorf("platform admin: err = %v, want ErrNoCustomer", err)
	}
}

func TestCustomer(t *testing.T) {
	viewer, _ := tenancy.NewUser(userID, "a@example.com", tenancy.Viewer, customer)
	if got, ok := viewer.Customer(); !ok || got != customer {
		t.Errorf("viewer belongs to %v, %v, want %v", got, ok, customer)
	}
	admin, _ := tenancy.NewUser(userID, "a@example.com", tenancy.PlatformAdmin, tenancy.CustomerID{})
	if _, ok := admin.Customer(); ok {
		t.Error("platform admin belongs to a customer")
	}
}

func TestNewCustomer(t *testing.T) {
	tests := []struct {
		name     string
		id       tenancy.CustomerID
		in       string
		wantName string
		wantErr  error
	}{
		{"trims the name", customer, "  Acme Corp\n", "Acme Corp", nil},
		{"blank name", customer, " \t", "", tenancy.ErrInvalidCustomer},
		{"zero id", tenancy.CustomerID{}, "Acme", "", tenancy.ErrInvalidCustomer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := tenancy.NewCustomer(tt.id, tt.in)
			if !errors.Is(err, tt.wantErr) || c.Name() != tt.wantName {
				t.Errorf("name = %q, err = %v, want %q, %v", c.Name(), err, tt.wantName, tt.wantErr)
			}
		})
	}
}

func TestOnlyAPlatformAdminManagesCustomers(t *testing.T) {
	tests := []struct {
		role     tenancy.Role
		customer tenancy.CustomerID
		want     error
	}{
		{tenancy.PlatformAdmin, tenancy.CustomerID{}, nil},
		{tenancy.CustomerAdmin, customer, tenancy.ErrNotPlatformAdmin},
		{tenancy.Viewer, customer, tenancy.ErrNotPlatformAdmin},
	}
	for _, tt := range tests {
		t.Run(tt.role.String(), func(t *testing.T) {
			u, err := tenancy.NewUser(userID, "a@example.com", tt.role, tt.customer)
			if err != nil {
				t.Fatal(err)
			}
			if err := u.ManageCustomers(); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestOnlyACustomerAdminManagesUsersAreasAndTheBusinessContext(t *testing.T) {
	actions := map[string]func(tenancy.User) (tenancy.CustomerID, error){
		"ManageUsers":         tenancy.User.ManageUsers,
		"ManageAreas":         tenancy.User.ManageAreas,
		"EditBusinessContext": tenancy.User.EditBusinessContext,
	}
	tests := []struct {
		role     tenancy.Role
		customer tenancy.CustomerID
		want     error
	}{
		{tenancy.CustomerAdmin, customer, nil},
		{tenancy.Viewer, customer, tenancy.ErrNotCustomerAdmin},
		{tenancy.PlatformAdmin, tenancy.CustomerID{}, tenancy.ErrNotCustomerAdmin},
	}
	for name, action := range actions {
		for _, tt := range tests {
			t.Run(name+"/"+tt.role.String(), func(t *testing.T) {
				u, err := tenancy.NewUser(userID, "a@example.com", tt.role, tt.customer)
				if err != nil {
					t.Fatal(err)
				}
				got, err := action(u)
				if !errors.Is(err, tt.want) || (err == nil && got != customer) {
					t.Errorf("%s = %v, %v, want %v, %v", name, got, err, customer, tt.want)
				}
			})
		}
	}
}

func TestACustomerKeepsAnActiveCustomerAdmin(t *testing.T) {
	tests := []struct {
		activeAdmins int
		want         error
	}{
		{0, tenancy.ErrLastCustomerAdmin},
		{1, nil},
	}
	for _, tt := range tests {
		if err := tenancy.RequireActiveCustomerAdmin(tt.activeAdmins); !errors.Is(err, tt.want) {
			t.Errorf("RequireActiveCustomerAdmin(%d) = %v, want %v", tt.activeAdmins, err, tt.want)
		}
	}
}

func TestWithRoleRefusesPlatformAdmin(t *testing.T) {
	u, _ := tenancy.NewUser(userID, "a@example.com", tenancy.Viewer, customer)
	if _, err := u.WithRole(tenancy.PlatformAdmin); !errors.Is(err, tenancy.ErrInvalidUser) {
		t.Errorf("err = %v, want ErrInvalidUser", err)
	}
}
