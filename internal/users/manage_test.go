package users_test

import (
	"context"
	"errors"
	"testing"

	"barbackend/internal/tenancy"
)

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
