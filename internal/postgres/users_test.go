package postgres_test

import (
	"context"
	"errors"
	"testing"

	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

func TestUserBySubRestoresTheStoredUser(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)
	customer := newCustomer(t, db)
	tests := []struct {
		name     string
		role     tenancy.Role
		customer tenancy.CustomerID
	}{
		{"viewer", tenancy.Viewer, customer},
		{"platform admin", tenancy.PlatformAdmin, tenancy.CustomerID{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want, err := tenancy.NewUser(tenancy.UserID(uuid.New()), uuid.NewString()+"@example.com", tt.role, tt.customer)
			if err != nil {
				t.Fatal(err)
			}
			sub := uuid.NewString()
			inTx(t, db, func(tx *postgres.Tx) error { return tx.CreateUser(context.Background(), want, sub) })

			var got tenancy.User
			inTx(t, db, func(tx *postgres.Tx) (err error) {
				got, err = tx.UserBySub(context.Background(), sub)
				return err
			})

			if got != want {
				t.Errorf("user = %+v, want %+v", got, want)
			}
		})
	}
}

func TestUserBySubWithUnknownSub(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)

	err := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.UserBySub(context.Background(), "unknown")
		return err
	})

	if !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func storeUser(t *testing.T, db *postgres.DB, email string, role tenancy.Role, customer tenancy.CustomerID) tenancy.User {
	t.Helper()
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), email, role, customer)
	if err != nil {
		t.Fatal(err)
	}
	inTx(t, db, func(tx *postgres.Tx) error { return tx.CreateUser(context.Background(), u, uuid.NewString()) })
	return u
}

func lockUser(db *postgres.DB, customer tenancy.CustomerID, id tenancy.UserID) (postgres.LockedUser, error) {
	var locked postgres.LockedUser
	err := db.InTx(context.Background(), func(tx *postgres.Tx) (err error) {
		locked, err = tx.LockUser(context.Background(), customer, id)
		return err
	})
	return locked, err
}

func TestUsersAreOnlyTheCustomersOrderedByEmail(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)
	customer, other := newCustomer(t, db), newCustomer(t, db)
	storeUser(t, db, "b@example.com", tenancy.Viewer, customer)
	storeUser(t, db, "a@example.com", tenancy.CustomerAdmin, customer)
	storeUser(t, db, "c@example.com", tenancy.Viewer, other)

	var got []postgres.StoredUser
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		got, err = tx.Users(context.Background(), customer)
		return err
	})

	if len(got) != 2 || got[0].User.Email() != "a@example.com" || got[1].User.Email() != "b@example.com" {
		t.Errorf("users = %+v, want a@example.com and b@example.com", got)
	}
}

func TestLockUserOfAnotherCustomerIsNotFound(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)
	customer, other := newCustomer(t, db), newCustomer(t, db)
	u := storeUser(t, db, "a@example.com", tenancy.Viewer, other)

	_, err := lockUser(db, customer, u.ID())

	if !errors.Is(err, postgres.ErrUserNotFound) {
		t.Errorf("err = %v, want ErrUserNotFound", err)
	}
}

// The test holds the Customer's lock and disables an admin while LockUser
// waits for it, which a count taken before the wait would miss.
func TestLockUserCountsTheActiveCustomerAdminsOnceLocked(t *testing.T) {
	t.Parallel()
	db, conn := newDBWithConn(t)
	customer := newCustomer(t, db)
	target := storeUser(t, db, "a@example.com", tenancy.CustomerAdmin, customer)
	other := storeUser(t, db, "b@example.com", tenancy.CustomerAdmin, customer)
	storeUser(t, db, "c@example.com", tenancy.Viewer, customer)
	holder, err := conn.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(context.Background(), "SELECT id FROM customers WHERE id = $1 FOR UPDATE", uuid.UUID(customer)); err != nil {
		t.Fatal(err)
	}

	done := make(chan postgres.LockedUser)
	go func() {
		locked, err := lockUser(db, customer, target.ID())
		if err != nil {
			t.Error(err)
		}
		done <- locked
	}()
	pgtest.WaitForLockWaiters(t, conn, 1)
	if _, err := holder.Exec(context.Background(), "UPDATE users SET disabled_at = now() WHERE id = $1", uuid.UUID(other.ID())); err != nil {
		t.Fatal(err)
	}
	if err := holder.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}

	if locked := <-done; locked.ActiveAdmins != 1 || locked.User.User != target || locked.Sub == "" {
		t.Errorf("locked = %+v, want %v with its sub and 1 active admin", locked, target.ID())
	}
}

func TestDisablingADisabledUserKeepsTheFirstTime(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)
	u := storeUser(t, db, "a@example.com", tenancy.Viewer, newCustomer(t, db))
	disable := func() postgres.StoredUser {
		var stored postgres.StoredUser
		inTx(t, db, func(tx *postgres.Tx) (err error) {
			stored, err = tx.DisableUser(context.Background(), u.ID())
			return err
		})
		return stored
	}

	first := disable()
	second := disable()

	if first.Disabled.IsZero() || !second.Disabled.Equal(first.Disabled) || second.User.CanSignIn() {
		t.Errorf("disabled at %v then %v, want the first time kept and the User unable to sign in", first.Disabled, second.Disabled)
	}
}
