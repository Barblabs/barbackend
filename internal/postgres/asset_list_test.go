package postgres_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
)

func TestListAssetsQueryCountIsIndependentOfPageSize(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	url := pgtest.URL(t)
	var queries atomic.Int64
	db, err := postgres.OpenTraced(ctx, url, func(string) { queries.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	customer := newCustomer(t, db)
	src := newSource(t, db, customer)
	var records []inventory.Record
	for i := range 20 {
		p := fullParams(t)
		p.Name = fmt.Sprintf("srv-%02d", i)
		records = append(records, record(t, fmt.Sprint(i), p))
	}
	syncRecords(t, db, src.ID(), records...)

	countFor := func(limit int) int64 {
		queries.Store(0)
		inTx(t, db, func(tx *postgres.Tx) error {
			page, err := tx.ListAssets(ctx, postgres.AssetListQuery{Customer: customer, Limit: limit})
			if err == nil && len(page.Assets) != limit {
				t.Errorf("page has %d assets, want %d", len(page.Assets), limit)
			}
			return err
		})
		return queries.Load()
	}

	if small, large := countFor(1), countFor(20); small != large {
		t.Errorf("queries for 1 asset = %d, for 20 = %d, want equal", small, large)
	}
}
