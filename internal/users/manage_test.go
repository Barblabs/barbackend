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

func TestDisableUserDisablesThemInCognitoAndPostgres(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{}
	svc, db := newService(t, admin)
	caller := customerAdmin(t, svc, db, admin)
	viewer, err := svc.InviteUser(context.Background(), caller, "viewer@example.com", tenancy.Viewer)
	if err != nil {
		t.Fatal(err)
	}
	sub := admin.created[len(admin.created)-1]

	if _, err := svc.DisableUser(context.Background(), caller, viewer.User.ID()); err != nil {
		t.Fatal(err)
	}

	if len(admin.disabled) != 1 || admin.disabled[0] != sub || userBySub(t, db, sub).CanSignIn() {
		t.Errorf("disabled in cognito = %v, want %s, and the stored User unable to sign in", admin.disabled, sub)
	}
}

func TestDisableUserStoresNothingWhenCognitoFails(t *testing.T) {
	t.Parallel()
	cognitoDown := errors.New("cognito unreachable")
	admin := &fakeAdmin{disableErr: cognitoDown}
	svc, db := newService(t, admin)
	caller := customerAdmin(t, svc, db, admin)
	viewer, err := svc.InviteUser(context.Background(), caller, "viewer@example.com", tenancy.Viewer)
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.DisableUser(context.Background(), caller, viewer.User.ID())

	if !errors.Is(err, cognitoDown) || !userBySub(t, db, admin.created[len(admin.created)-1]).CanSignIn() {
		t.Errorf("err = %v, want the Cognito failure and the User still able to sign in", err)
	}
}

func TestDisablingTheLastCustomerAdminLeavesThemInCognito(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{}
	svc, db := newService(t, admin)
	caller := customerAdmin(t, svc, db, admin)

	_, err := svc.DisableUser(context.Background(), caller, caller.ID())

	if !errors.Is(err, tenancy.ErrLastCustomerAdmin) || len(admin.disabled) != 0 {
		t.Errorf("err = %v, disabled in cognito = %v, want ErrLastCustomerAdmin and nobody disabled", err, admin.disabled)
	}
}
