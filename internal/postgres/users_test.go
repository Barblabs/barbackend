package postgres_test

import (
	"context"
	"errors"
	"testing"

	"barbackend/internal/postgres"
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
