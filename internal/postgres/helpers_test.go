package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func inTx(t *testing.T, db *postgres.DB, fn func(*postgres.Tx) error) {
	t.Helper()
	if err := db.InTx(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

func newSource(t *testing.T, db *postgres.DB, customer tenancy.CustomerID) inventory.CMDBSource {
	t.Helper()
	src, err := inventory.NewCMDBSource(inventory.CMDBSourceID(uuid.New()), customer, "itop")
	if err != nil {
		t.Fatal(err)
	}
	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.CreateCMDBSource(context.Background(), src, []byte(`{}`), []byte{})
	})
	return src
}

func newCustomer(t *testing.T, db *postgres.DB) tenancy.CustomerID {
	t.Helper()
	id := tenancy.CustomerID(uuid.New())
	if err := db.CreateCustomer(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	return id
}

func mustImported(t *testing.T, p inventory.ImportedAssetParams) inventory.ImportedAsset {
	t.Helper()
	a, err := inventory.NewImportedAsset(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

var errReadOnly = errors.New("read only")

func assets(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID) []*inventory.Asset {
	t.Helper()
	return stored(t, db, src).Assets
}

func stored(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID) inventory.Stored {
	t.Helper()
	var got inventory.Stored
	_, err := db.CommitSync(context.Background(), src, time.Now(), func(existing inventory.Stored) (inventory.Reconciliation, error) {
		got = existing
		return inventory.Reconciliation{}, errReadOnly
	})
	if !errors.Is(err, errReadOnly) {
		t.Fatal(err)
	}
	return got
}

func reconcileWith(src inventory.CMDBSourceID, s inventory.Snapshot) func(inventory.Stored) (inventory.Reconciliation, error) {
	return func(existing inventory.Stored) (inventory.Reconciliation, error) {
		return inventory.Reconcile(src, existing, s)
	}
}

func commitSync(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID, reconcile func(inventory.Stored) (inventory.Reconciliation, error)) inventory.SyncRun {
	t.Helper()
	run, err := db.CommitSync(context.Background(), src, time.Now(), reconcile)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func syncRecords(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID, records ...inventory.Record) inventory.Reconciliation {
	t.Helper()
	return syncSnapshot(t, db, src, inventory.Snapshot{Records: records})
}

func syncSnapshot(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID, s inventory.Snapshot) inventory.Reconciliation {
	t.Helper()
	var r inventory.Reconciliation
	reconcile := reconcileWith(src, s)
	commitSync(t, db, src, func(existing inventory.Stored) (inventory.Reconciliation, error) {
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

// onlyAsset is the one Asset of the Customer, as the Asset list reads it.
func onlyAsset(t *testing.T, db *postgres.DB, customer tenancy.CustomerID) postgres.StoredAsset {
	t.Helper()
	var page postgres.AssetPage
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		page, err = tx.ListAssets(context.Background(), postgres.AssetListQuery{Customer: customer, Limit: 10})
		return err
	})
	if len(page.Assets) != 1 {
		t.Fatalf("assets = %d, want 1", len(page.Assets))
	}
	return page.Assets[0]
}

func declareInternal(t *testing.T, db *postgres.DB, customer tenancy.CustomerID, id int64, by tenancy.UserID) {
	t.Helper()
	inTx(t, db, func(tx *postgres.Tx) error {
		stored, err := tx.CustomerAsset(context.Background(), customer, id)
		if err != nil {
			return err
		}
		if err := stored.Asset.DeclareExposure(inventory.Internal); err != nil {
			return err
		}
		return tx.DeclareExposure(context.Background(), stored.Asset, by)
	})
}

func declareConfidential(t *testing.T, db *postgres.DB, customer tenancy.CustomerID, id int64, by tenancy.UserID) {
	t.Helper()
	inTx(t, db, func(tx *postgres.Tx) error {
		stored, err := tx.CustomerAsset(context.Background(), customer, id)
		if err != nil {
			return err
		}
		if err := stored.Asset.DeclareInformationClassification(inventory.ClassifiedConfidential); err != nil {
			return err
		}
		return tx.DeclareInformationClassification(context.Background(), stored.Asset, by)
	})
}
