package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"barbackend/internal/inventory"
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
	change := func(fn func(*postgres.Tx, context.Context, tenancy.CustomerID) (postgres.StoredCustomer, error)) postgres.StoredCustomer {
		var stored postgres.StoredCustomer
		inTx(t, db, func(tx *postgres.Tx) (err error) {
			stored, err = fn(tx, context.Background(), c.Customer.ID())
			return err
		})
		return stored
	}

	first := change((*postgres.Tx).DeactivateCustomer)
	again := change((*postgres.Tx).DeactivateCustomer)
	reactivated := change((*postgres.Tx).ReactivateCustomer)

	if first.Deactivated.IsZero() || !again.Deactivated.Equal(first.Deactivated) {
		t.Errorf("deactivated at %v, then %v, want the first time kept", first.Deactivated, again.Deactivated)
	}
	if !reactivated.Deactivated.IsZero() {
		t.Errorf("deactivated at %v after reactivating, want zero", reactivated.Deactivated)
	}
}

func TestCommitSyncOfADeactivatedCustomerFails(t *testing.T) {
	t.Parallel()
	db, conn := newDBWithConn(t)
	customer := newCustomer(t, db)
	src := newSource(t, db, customer)
	inTx(t, db, func(tx *postgres.Tx) error {
		_, err := tx.DeactivateCustomer(context.Background(), customer)
		return err
	})

	_, err := db.CommitSync(context.Background(), src.ID(), time.Now(), reconcileWith(src.ID(), inventory.Snapshot{Records: []inventory.Record{record(t, "1", fullParams(t))}}))

	if !errors.Is(err, postgres.ErrCustomerDeactivated) {
		t.Errorf("err = %v, want ErrCustomerDeactivated", err)
	}
	if n := queryInt(t, conn, "SELECT count(*) FROM assets") + queryInt(t, conn, "SELECT count(*) FROM sync_runs"); n != 0 {
		t.Errorf("rows written = %d, want 0", n)
	}
}
