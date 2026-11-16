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

	if !errors.Is(createErr, tenancy.ErrCustomerNameTaken) || !errors.Is(renameErr, tenancy.ErrCustomerNameTaken) {
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

	if !errors.Is(err, tenancy.ErrCustomerDeactivated) {
		t.Errorf("err = %v, want ErrCustomerDeactivated", err)
	}
	if n := queryInt(t, conn, "SELECT count(*) FROM assets") + queryInt(t, conn, "SELECT count(*) FROM sync_runs"); n != 0 {
		t.Errorf("rows written = %d, want 0", n)
	}
}

func TestCustomerStatsCountEnabledUsersAndTellTheLatestSyncs(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)
	acme, err := storeCustomer(db, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storeCustomer(db, "Beta"); err != nil {
		t.Fatal(err)
	}
	a := acme.Customer.ID()
	storeUser(t, db, "ana@acme.example", tenancy.CustomerAdmin, a)
	storeUser(t, db, "bob@acme.example", tenancy.Viewer, a)
	gone := storeUser(t, db, "eve@acme.example", tenancy.Viewer, a)
	storeUser(t, db, "staff@barbattack.example", tenancy.PlatformAdmin, tenancy.CustomerID{})
	inTx(t, db, func(tx *postgres.Tx) error {
		_, err := tx.DisableUser(context.Background(), a, gone.ID())
		return err
	})
	src := newSource(t, db, a)
	succeeded := commitSync(t, db, src.ID(), reconcileWith(src.ID(), inventory.Snapshot{})).Finished()
	failedAt := succeeded.Add(time.Hour).Truncate(time.Microsecond)
	failed, err := inventory.FailedRun(src.ID(), failedAt, failedAt, errors.New("cmdb unreachable"))
	if err != nil {
		t.Fatal(err)
	}
	inTx(t, db, func(tx *postgres.Tx) error { return tx.RecordFailedSync(context.Background(), failed) })

	stats := inTxValue(t, db, func(tx *postgres.Tx) ([]postgres.CustomerStats, error) { return tx.CustomerStats(context.Background()) })

	if len(stats) != 2 || stats[0].Customer.Customer.Name() != "acme" || stats[1].Customer.Customer.Name() != "Beta" {
		t.Fatalf("stats = %+v, want acme then Beta", stats)
	}
	got := stats[0]
	if got.Users != 2 || !got.Connected {
		t.Errorf("acme: users = %d, connected = %v, want 2 and true", got.Users, got.Connected)
	}
	if !got.LastSync.Equal(succeeded) || !got.LastSyncFailed.Equal(failedAt) {
		t.Errorf("acme: last sync = %v, failed = %v, want %v and %v", got.LastSync, got.LastSyncFailed, succeeded, failedAt)
	}
	if empty := stats[1]; empty.Users != 0 || empty.Connected || !empty.LastSync.IsZero() || !empty.LastSyncFailed.IsZero() {
		t.Errorf("Beta = %+v, want no Users, no CMDB Source and no Sync", empty)
	}
}
