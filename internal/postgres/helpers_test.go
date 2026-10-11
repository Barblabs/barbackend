package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func inTx(t *testing.T, db *postgres.DB, fn func(*postgres.Tx) error) {
	t.Helper()
	if err := db.InTx(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

func newSource(t *testing.T, db *postgres.DB, customer inventory.CustomerID) inventory.CMDBSource {
	t.Helper()
	src, err := inventory.NewCMDBSource(inventory.CMDBSourceID(uuid.New()), customer, "itop")
	if err != nil {
		t.Fatal(err)
	}
	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.CreateCMDBSource(context.Background(), src, []byte(`{}`))
	})
	return src
}

func newCustomer() inventory.CustomerID { return inventory.CustomerID(uuid.New()) }

func mustImported(t *testing.T, p inventory.ImportedAssetParams) inventory.ImportedAsset {
	t.Helper()
	a, err := inventory.NewImportedAsset(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

var errReadOnly = errors.New("read only")

// assets reads the stored Assets through the interface a Sync uses, then
// aborts so nothing is written.
func assets(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID) []*inventory.Asset {
	t.Helper()
	var got []*inventory.Asset
	_, err := db.CommitSync(context.Background(), src, time.Now(), func(existing []*inventory.Asset) (inventory.Reconciliation, error) {
		got = existing
		return inventory.Reconciliation{}, errReadOnly
	})
	if !errors.Is(err, errReadOnly) {
		t.Fatal(err)
	}
	return got
}

// reconcileWith reconciles the stored Assets with s, as a Sync does.
func reconcileWith(src inventory.CMDBSourceID, s inventory.Snapshot) func([]*inventory.Asset) (inventory.Reconciliation, error) {
	return func(existing []*inventory.Asset) (inventory.Reconciliation, error) {
		return inventory.Reconcile(src, existing, s)
	}
}

func commitSync(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID, reconcile func([]*inventory.Asset) (inventory.Reconciliation, error)) inventory.SyncRun {
	t.Helper()
	run, err := db.CommitSync(context.Background(), src, time.Now(), reconcile)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

// syncRecords commits a Sync of a snapshot of records.
func syncRecords(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID, records ...inventory.Record) inventory.Reconciliation {
	t.Helper()
	var r inventory.Reconciliation
	reconcile := reconcileWith(src, inventory.Snapshot{Records: records})
	commitSync(t, db, src, func(existing []*inventory.Asset) (inventory.Reconciliation, error) {
		var err error
		r, err = reconcile(existing)
		return r, err
	})
	return r
}

func newDBWithConn(t *testing.T) (*postgres.DB, *pgx.Conn) {
	t.Helper()
	url := pgtest.URL(t)
	db, err := postgres.Open(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db, pgtest.Conn(t, url)
}

func queryInt(t *testing.T, conn *pgx.Conn, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := conn.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func mustOwner(t *testing.T, email string) inventory.OwnerEmail {
	t.Helper()
	o, err := inventory.NewOwnerEmail(email)
	if err != nil {
		t.Fatal(err)
	}
	return o
}
