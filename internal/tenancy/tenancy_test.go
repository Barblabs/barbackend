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

func TestCanSignIn(t *testing.T) {
	tests := []struct {
		name  string
		state tenancy.UserState
		want  bool
	}{
		{"active", tenancy.UserState{}, true},
		{"disabled", tenancy.UserState{Disabled: true}, false},
		{"deactivated customer", tenancy.UserState{CustomerDeactivated: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := tenancy.RestoreUser(userID, "a@example.com", tenancy.Viewer, customer, tt.state)
			if err != nil {
				t.Fatal(err)
			}
			if got := u.CanSignIn(); got != tt.want {
				t.Errorf("CanSignIn = %v, want %v", got, tt.want)
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
