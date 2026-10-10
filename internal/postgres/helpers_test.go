package postgres_test

import (
	"context"
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

func assets(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID) []*inventory.Asset {
	t.Helper()
	var got []*inventory.Asset
	inSource(t, db, src, func(tx *postgres.SourceTx) error {
		var err error
		got, err = tx.Assets(context.Background())
		return err
	})
	return got
}

func inSource(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID, fn func(*postgres.SourceTx) error) {
	t.Helper()
	if err := db.InLockedSource(context.Background(), src, time.Now(), fn); err != nil {
		t.Fatal(err)
	}
}

// syncRecords saves the reconciliation of the stored Assets with a snapshot
// of records, as a Sync does.
func syncRecords(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID, records ...inventory.Record) inventory.Reconciliation {
	t.Helper()
	var r inventory.Reconciliation
	inSource(t, db, src, func(tx *postgres.SourceTx) error {
		existing, err := tx.Assets(context.Background())
		if err != nil {
			return err
		}
		r, err = inventory.Reconcile(src, existing, inventory.Snapshot{Records: records})
		if err != nil {
			return err
		}
		return save(tx, r)
	})
	return r
}

func save(tx *postgres.SourceTx, r inventory.Reconciliation) error {
	now := time.Now()
	run, err := inventory.SucceededRun(r, now, now)
	if err != nil {
		return err
	}
	return tx.Save(context.Background(), r, run)
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
