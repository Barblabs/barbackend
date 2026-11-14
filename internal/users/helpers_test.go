package users_test

import (
	"context"
	"testing"

	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
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

func newService(t *testing.T, admin users.Admin) (*users.Service, *postgres.DB) {
	t.Helper()
	db, err := postgres.Open(context.Background(), pgtest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return users.New(db, nil, admin), db
}
