package users_test

import (
	"context"
	"errors"
	"testing"

	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"barbackend/internal/users"
	"github.com/google/uuid"
)

func platformAdmin(t *testing.T) tenancy.User {
	t.Helper()
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "staff@example.com", tenancy.PlatformAdmin, tenancy.CustomerID{})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestCreateCustomerStoresItWithItsFirstCustomerAdmin(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{}
	svc, db := newService(t, admin)

	c, err := svc.CreateCustomer(context.Background(), platformAdmin(t), "Acme", "Ana@Example.com")
	if err != nil {
		t.Fatal(err)
	}

	if len(admin.created) != 1 {
		t.Fatalf("invited %d users, want 1", len(admin.created))
	}
	var stored tenancy.User
	if err := db.InTx(context.Background(), func(tx *postgres.Tx) (err error) {
		stored, err = tx.UserBySub(context.Background(), admin.created[0])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	actsFor, _ := stored.ActsFor()
	if stored.Role() != tenancy.CustomerAdmin || actsFor != c.Customer.ID() || stored.Email() != "ana@example.com" {
		t.Errorf("stored %s %s for %s, want Customer Admin ana@example.com for %s", stored.Role(), stored.Email(), actsFor, c.Customer.ID())
	}
}

func TestCreateCustomerWithATakenNameSendsNoInvitation(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{}
	svc, _ := newService(t, admin)
	if _, err := svc.CreateCustomer(context.Background(), platformAdmin(t), "Acme", "a@example.com"); err != nil {
		t.Fatal(err)
	}

	_, err := svc.CreateCustomer(context.Background(), platformAdmin(t), "acme", "b@example.com")

	if !errors.Is(err, users.ErrCustomerNameTaken) || len(admin.created) != 1 {
		t.Errorf("err = %v, invited %d users, want ErrCustomerNameTaken and only the first invitation", err, len(admin.created))
	}
}

// The admin's email is stored already, so storing them fails after Cognito
// created the user.
func TestCreateCustomerStoresNothingWhenItsAdminCannotBeStored(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{}
	svc, _ := newService(t, admin)
	caller := platformAdmin(t)
	if _, err := svc.CreateCustomer(context.Background(), caller, "Acme", "a@example.com"); err != nil {
		t.Fatal(err)
	}

	_, err := svc.CreateCustomer(context.Background(), caller, "Globex", "a@example.com")

	customers, listErr := svc.Customers(context.Background(), caller)
	if listErr != nil {
		t.Fatal(listErr)
	}
	if err == nil || len(customers) != 1 || len(admin.deleted) != 1 {
		t.Errorf("err = %v, customers = %d, deleted = %v, want an error, only Acme stored and the Cognito user deleted", err, len(customers), admin.deleted)
	}
}
