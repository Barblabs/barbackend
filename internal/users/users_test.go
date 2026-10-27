package users_test

import (
	"context"
	"errors"
	"testing"

	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/tenancy"
	"barbackend/internal/users"
	"github.com/google/uuid"
)

// fakeAdmin is a user pool that accepts every email, as Cognito would for
// an email it has not seen.
type fakeAdmin struct {
	deleteErr  error
	disableErr error
	created    []string
	disabled   []string
	deleted    []string
}

func (a *fakeAdmin) CreateUser(context.Context, string) (string, error) {
	sub := uuid.NewString()
	a.created = append(a.created, sub)
	return sub, nil
}

func (a *fakeAdmin) DisableUser(_ context.Context, sub string) error {
	if a.disableErr != nil {
		return a.disableErr
	}
	a.disabled = append(a.disabled, sub)
	return nil
}

func (a *fakeAdmin) DeleteUser(_ context.Context, sub string) error {
	a.deleted = append(a.deleted, sub)
	return a.deleteErr
}

func newService(t *testing.T, admin users.Admin) (*users.Service, *postgres.DB) {
	t.Helper()
	db, err := postgres.Open(context.Background(), pgtest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return users.New(db, nil, admin), db
}

func TestCreateStoresThePlatformAdmin(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{}
	svc, db := newService(t, admin)

	created, err := svc.Create(context.Background(), "admin@example.com", tenancy.PlatformAdmin, tenancy.CustomerID{})
	if err != nil {
		t.Fatal(err)
	}

	var stored tenancy.User
	if err := db.InTx(context.Background(), func(tx *postgres.Tx) (err error) {
		stored, err = tx.UserBySub(context.Background(), admin.created[0])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if stored != created.User || stored.Role() != tenancy.PlatformAdmin || len(admin.deleted) != 0 {
		t.Errorf("stored = %+v, created = %+v, deleted = %v, want the platform admin stored under its sub", stored, created, admin.deleted)
	}
}

// The second insert fails on the stored email, after Cognito created the user.
func TestCreateDeletesTheCognitoUserWhenStoringFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		deleteErr error
	}{
		{"delete succeeds", nil},
		{"delete fails too", errors.New("cognito unreachable")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			admin := &fakeAdmin{deleteErr: tt.deleteErr}
			svc, _ := newService(t, admin)
			if _, err := svc.Create(context.Background(), "a@example.com", tenancy.PlatformAdmin, tenancy.CustomerID{}); err != nil {
				t.Fatal(err)
			}

			_, err := svc.Create(context.Background(), "a@example.com", tenancy.PlatformAdmin, tenancy.CustomerID{})

			if err == nil || len(admin.deleted) != 1 {
				t.Fatalf("err = %v, deleted = %v, want an error and one deleted user", err, admin.deleted)
			}
			if tt.deleteErr != nil && !errors.Is(err, tt.deleteErr) {
				t.Errorf("err = %v, want it to carry the delete failure", err)
			}
		})
	}
}
