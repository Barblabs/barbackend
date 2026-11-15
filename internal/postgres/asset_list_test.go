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
	db, conn := newDBWithConn(t)
	customer := newCustomer(t, db)
	src := newSource(t, db, customer)
	asset := func(id string, kind inventory.AssetKind, criticality inventory.Criticality, exposure inventory.Exposure, area string) inventory.Record {
		return record(t, id, inventory.ImportedAssetParams{Name: "asset-" + id, Kind: kind, Criticality: criticality, Exposure: exposure, Area: area})
	}
	active := []inventory.Record{
		asset("1", inventory.Server, inventory.CriticalityHigh, inventory.InternetFacing, "it"),
		asset("2", inventory.Server, inventory.CriticalityUnknown, inventory.Internal, "it"),
		asset("3", inventory.VirtualMachine, inventory.CriticalityLow, inventory.ExposureUnknown, "legacy"),
		asset("4", inventory.VirtualMachine, inventory.CriticalityUnknown, inventory.ExposureUnknown, ""),
		asset("5", inventory.Workstation, inventory.CriticalityMedium, inventory.InternetFacing, "legacy"),
	}
	inactive := asset("6", inventory.Workstation, inventory.CriticalityHigh, inventory.Internal, "")
	areas := []inventory.AreaRecord{areaRecord(t, "it", "IT", false), areaRecord(t, "legacy", "Legacy", true)}
	snapshot := func(records []inventory.Record) inventory.Snapshot {
		return inventory.Snapshot{Areas: areas, Records: records}
	}
	syncSnapshot(t, db, src.ID(), snapshot(append(active, inactive)))
	syncSnapshot(t, db, src.ID(), snapshot(active))
	activeOnly := true
	admin := storeUser(t, db, "admin@example.com", tenancy.CustomerAdmin, customer)
	workstation := inTxValue(t, db, func(tx *postgres.Tx) (postgres.AssetPage, error) {
		return tx.ListAssets(ctx, postgres.AssetListQuery{Customer: customer, Filter: postgres.AssetFilter{Active: &activeOnly, Kind: []inventory.AssetKind{inventory.Workstation}}, Limit: 1})
	})
	declareInternal(t, db, customer, workstation.Assets[0].ID, admin.ID())
	areaID := func(record string) int64 {
		return int64(queryInt(t, conn, "SELECT id FROM customer_areas WHERE record_id = $1", record))
	}
	declareConfidential(t, db, customer, int64(queryInt(t, conn, "SELECT id FROM assets WHERE record_id = '1'")), admin.ID())
	it, legacy := areaID("it"), areaID("legacy")

	tests := []struct {
		name   string
		filter postgres.AssetFilter
		want   []string
	}{
		{"no filter", postgres.AssetFilter{}, []string{"1", "2", "3", "4", "5", "6"}},
		{"active", postgres.AssetFilter{Active: &activeOnly}, []string{"1", "2", "3", "4", "5"}},
		{"kinds", postgres.AssetFilter{Kind: []inventory.AssetKind{inventory.Server, inventory.Workstation}}, []string{"1", "2", "5", "6"}},
		{"criticality", postgres.AssetFilter{Criticality: []inventory.Criticality{inventory.CriticalityHigh}}, []string{"1", "6"}},
		{"unknown criticality", postgres.AssetFilter{Criticality: []inventory.Criticality{inventory.CriticalityUnknown}}, []string{"2", "4"}},
		{"criticalities with unknown", postgres.AssetFilter{Criticality: []inventory.Criticality{inventory.CriticalityUnknown, inventory.CriticalityLow}}, []string{"2", "3", "4"}},
		{"exposure", postgres.AssetFilter{Exposure: []inventory.Exposure{inventory.InternetFacing}}, []string{"1"}},
		{"declared exposure", postgres.AssetFilter{Exposure: []inventory.Exposure{inventory.Internal}}, []string{"2", "5", "6"}},
		{"unknown exposure", postgres.AssetFilter{Exposure: []inventory.Exposure{inventory.ExposureUnknown}}, []string{"3", "4"}},
		{"exposures with unknown", postgres.AssetFilter{Exposure: []inventory.Exposure{inventory.ExposureUnknown, inventory.Internal}}, []string{"2", "3", "4", "5", "6"}},
		{"confidential", postgres.AssetFilter{InformationClassification: []inventory.InformationClassification{inventory.ClassifiedConfidential}}, []string{"1"}},
		{"unclassified", postgres.AssetFilter{InformationClassification: []inventory.InformationClassification{inventory.Unclassified}}, []string{"2", "3", "4", "5", "6"}},
		{"classifications with unclassified", postgres.AssetFilter{InformationClassification: []inventory.InformationClassification{inventory.ClassifiedConfidential, inventory.Unclassified}}, []string{"1", "2", "3", "4", "5", "6"}},
		{"area", postgres.AssetFilter{Area: []int64{it}}, []string{"1", "2"}},
		{"areas", postgres.AssetFilter{Area: []int64{it, legacy}}, []string{"1", "2", "3", "5"}},
		{"inactive area", postgres.AssetFilter{Area: []int64{legacy}}, []string{"3", "5"}},
		{"unknown area", postgres.AssetFilter{Area: []int64{it + legacy + 1}}, nil},
		{"combination", postgres.AssetFilter{
			Active:      &activeOnly,
			Kind:        []inventory.AssetKind{inventory.Server, inventory.VirtualMachine},
			Criticality: []inventory.Criticality{inventory.CriticalityUnknown, inventory.CriticalityHigh},
			Exposure:    []inventory.Exposure{inventory.InternetFacing, inventory.ExposureUnknown},
		}, []string{"1", "4"}},
		{"classification and area", postgres.AssetFilter{
			InformationClassification: []inventory.InformationClassification{inventory.ClassifiedConfidential},
			Area:                      []int64{it},
		}, []string{"1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := postgres.AssetListQuery{Customer: customer, Filter: tt.filter, Limit: 1}
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
