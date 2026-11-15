package postgres_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/tenancy"
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

func TestListAssetsTotalCountsTheAssetsListedAcrossAllPages(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, _ := newDBWithConn(t)
	customer := newCustomer(t, db)
	src := newSource(t, db, customer)
	asset := func(id string, kind inventory.AssetKind, criticality inventory.Criticality, exposure inventory.Exposure) inventory.Record {
		return record(t, id, inventory.ImportedAssetParams{Name: "asset-" + id, Kind: kind, Criticality: criticality, Exposure: exposure})
	}
	active := []inventory.Record{
		asset("1", inventory.Server, inventory.CriticalityHigh, inventory.InternetFacing),
		asset("2", inventory.Server, inventory.CriticalityUnknown, inventory.Internal),
		asset("3", inventory.VirtualMachine, inventory.CriticalityLow, inventory.ExposureUnknown),
		asset("4", inventory.VirtualMachine, inventory.CriticalityUnknown, inventory.ExposureUnknown),
		asset("5", inventory.Workstation, inventory.CriticalityMedium, inventory.InternetFacing),
	}
	syncRecords(t, db, src.ID(), append(active, asset("6", inventory.Workstation, inventory.CriticalityHigh, inventory.Internal))...)
	syncRecords(t, db, src.ID(), active...)
	activeOnly := true
	admin := storeUser(t, db, "admin@example.com", tenancy.CustomerAdmin, customer)
	workstation := inTxValue(t, db, func(tx *postgres.Tx) (postgres.AssetPage, error) {
		return tx.ListAssets(ctx, postgres.AssetListQuery{Customer: customer, Active: &activeOnly, Kind: []inventory.AssetKind{inventory.Workstation}, Limit: 1})
	})
	declareInternal(t, db, customer, workstation.Assets[0].ID, admin.ID())

	tests := []struct {
		name  string
		query postgres.AssetListQuery
		want  []string
	}{
		{"no filter", postgres.AssetListQuery{}, []string{"1", "2", "3", "4", "5", "6"}},
		{"active", postgres.AssetListQuery{Active: &activeOnly}, []string{"1", "2", "3", "4", "5"}},
		{"kinds", postgres.AssetListQuery{Kind: []inventory.AssetKind{inventory.Server, inventory.Workstation}}, []string{"1", "2", "5", "6"}},
		{"criticality", postgres.AssetListQuery{Criticality: []inventory.Criticality{inventory.CriticalityHigh}}, []string{"1", "6"}},
		{"unknown criticality", postgres.AssetListQuery{Criticality: []inventory.Criticality{inventory.CriticalityUnknown}}, []string{"2", "4"}},
		{"criticalities with unknown", postgres.AssetListQuery{Criticality: []inventory.Criticality{inventory.CriticalityUnknown, inventory.CriticalityLow}}, []string{"2", "3", "4"}},
		{"exposure", postgres.AssetListQuery{Exposure: []inventory.Exposure{inventory.InternetFacing}}, []string{"1"}},
		{"declared exposure", postgres.AssetListQuery{Exposure: []inventory.Exposure{inventory.Internal}}, []string{"2", "5", "6"}},
		{"unknown exposure", postgres.AssetListQuery{Exposure: []inventory.Exposure{inventory.ExposureUnknown}}, []string{"3", "4"}},
		{"exposures with unknown", postgres.AssetListQuery{Exposure: []inventory.Exposure{inventory.ExposureUnknown, inventory.Internal}}, []string{"2", "3", "4", "5", "6"}},
		{"combination", postgres.AssetListQuery{
			Active:      &activeOnly,
			Kind:        []inventory.AssetKind{inventory.Server, inventory.VirtualMachine},
			Criticality: []inventory.Criticality{inventory.CriticalityUnknown, inventory.CriticalityHigh},
			Exposure:    []inventory.Exposure{inventory.InternetFacing, inventory.ExposureUnknown},
		}, []string{"1", "4"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := tt.query
			query.Customer, query.Limit = customer, 1
			var listed []string
			totals := map[int]bool{}
			for {
				page := inTxValue(t, db, func(tx *postgres.Tx) (postgres.AssetPage, error) { return tx.ListAssets(ctx, query) })
				totals[page.Total] = true
				for _, a := range page.Assets {
					listed = append(listed, a.Asset.Ref().RecordID)
				}
				if !page.More || len(listed) > len(tt.want) {
					break
				}
				last := page.Assets[len(page.Assets)-1].Asset
				query.After = &postgres.AssetPosition{Name: last.Imported().Name(), Ref: last.Ref()}
			}
			if fmt.Sprint(listed) != fmt.Sprint(tt.want) || len(totals) != 1 || !totals[len(listed)] {
				t.Errorf("listed %v with totals %v, want %v with total %d", listed, totals, tt.want, len(tt.want))
			}
		})
	}
}
