package postgres_test

import (
	"context"
	"errors"
	"testing"

	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

func storeCustomer(db *postgres.DB, name string) (postgres.StoredCustomer, error) {
	c, err := tenancy.NewCustomer(tenancy.CustomerID(uuid.New()), name)
	if err != nil {
		return postgres.StoredCustomer{}, err
	}
	var stored postgres.StoredCustomer
	err = db.InTx(context.Background(), func(tx *postgres.Tx) (err error) {
		stored, err = tx.CreateCustomer(context.Background(), c)
		return err
	})
	return stored, err
}

func TestCustomerNamesAreUniqueRegardlessOfCase(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)
	if _, err := storeCustomer(db, "Acme"); err != nil {
		t.Fatal(err)
	}
	other, err := storeCustomer(db, "Globex")
	if err != nil {
		t.Fatal(err)
	}

	_, createErr := storeCustomer(db, "ACME")
	renamed, err := tenancy.NewCustomer(other.Customer.ID(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	renameErr := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.RenameCustomer(context.Background(), renamed)
		return err
	})

	if !errors.Is(createErr, postgres.ErrCustomerNameTaken) || !errors.Is(renameErr, postgres.ErrCustomerNameTaken) {
		t.Errorf("create err = %v, rename err = %v, want ErrCustomerNameTaken for both", createErr, renameErr)
	}
}

func TestDeactivatingADeactivatedCustomerKeepsTheFirstTime(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)
	c, err := storeCustomer(db, "Acme")
	if err != nil {
		t.Fatal(err)
	}
	setDeactivated := func(deactivated bool) postgres.StoredCustomer {
		var stored postgres.StoredCustomer
		inTx(t, db, func(tx *postgres.Tx) (err error) {
			stored, err = tx.SetCustomerDeactivated(context.Background(), c.Customer.ID(), deactivated)
			return err
		})
		return stored
	}

	first := setDeactivated(true)
	again := setDeactivated(true)
	reactivated := setDeactivated(false)

	if first.Deactivated.IsZero() || !again.Deactivated.Equal(first.Deactivated) {
		t.Errorf("deactivated at %v, then %v, want the first time kept", first.Deactivated, again.Deactivated)
	}
	if !reactivated.Deactivated.IsZero() {
		t.Errorf("deactivated at %v after reactivating, want zero", reactivated.Deactivated)
	}
}
