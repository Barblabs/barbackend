package postgres_test

import (
	"context"
	"testing"

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
	src, err := inventory.NewCMDBSource(inventory.CMDBSourceID(uuid.NewString()), customer, "itop")
	if err != nil {
		t.Fatal(err)
	}
	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.CreateCMDBSource(context.Background(), src, []byte(`{}`))
	})
	return src
}

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
	inTx(t, db, func(tx *postgres.Tx) error {
		var err error
		got, err = tx.Assets(context.Background(), src)
		return err
	})
	return got
}

// newDBWithConn also returns a raw connection, for asserting on rows the
// store does not expose.
func newDBWithConn(t *testing.T) (*postgres.DB, *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	url := pgtest.URL(t)
	db, err := postgres.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	return db, conn
}

func queryInt(t *testing.T, conn *pgx.Conn, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := conn.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
