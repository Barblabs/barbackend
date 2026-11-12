package users_test

import (
	"context"
	"errors"
	"testing"

	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"barbackend/internal/users"
)

// customerAdmin creates a Customer and returns its first Customer Admin.
func customerAdmin(t *testing.T, svc *users.Service, db *postgres.DB, admin *fakeAdmin) tenancy.User {
	t.Helper()
	if _, err := svc.CreateCustomer(context.Background(), platformAdmin(t), "Acme", "admin@example.com"); err != nil {
		t.Fatal(err)
	}
	return userBySub(t, db, admin.created[len(admin.created)-1])
}

func userBySub(t *testing.T, db *postgres.DB, sub string) tenancy.User {
	t.Helper()
	var u tenancy.User
	if err := db.InTx(context.Background(), func(tx *postgres.Tx) (err error) {
		u, err = tx.UserBySub(context.Background(), sub)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestDisabledUserIsRefusedAtOnce(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{}
	svc, db := newService(t, admin)
	caller := customerAdmin(t, svc, db, admin)
	viewer, err := svc.InviteUser(context.Background(), caller, "viewer@example.com", tenancy.Viewer)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.DisableUser(context.Background(), caller, viewer.User.ID()); err != nil {
		t.Fatal(err)
	}

	if err := userBySub(t, db, admin.created[len(admin.created)-1]).SignIn(); !errors.Is(err, tenancy.ErrUserDisabled) {
		t.Errorf("sign in after disabling: err = %v, want ErrUserDisabled", err)
	}
}

func TestDisablingTheLastCustomerAdminIsRefused(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{}
	svc, db := newService(t, admin)
	caller := customerAdmin(t, svc, db, admin)

	_, err := svc.DisableUser(context.Background(), caller, caller.ID())

	if !errors.Is(err, tenancy.ErrLastCustomerAdmin) || userBySub(t, db, admin.created[0]).SignIn() != nil {
		t.Errorf("err = %v, want ErrLastCustomerAdmin and the admin still able to sign in", err)
	}
}

func TestAPendingCustomerAdminDoesNotKeepTheCustomerManaged(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{}
	svc, db := newService(t, admin)
	caller := customerAdmin(t, svc, db, admin)
	admin.err = errors.New("cognito unreachable")
	if _, err := svc.InviteUser(context.Background(), caller, "second@example.com", tenancy.CustomerAdmin); err != nil {
		t.Fatal(err)
	}

	_, err := svc.DisableUser(context.Background(), caller, caller.ID())

	if !errors.Is(err, tenancy.ErrLastCustomerAdmin) {
		t.Errorf("err = %v, want ErrLastCustomerAdmin while the other Customer Admin is pending", err)
	}
}
