package postgres

import (
	"context"
	"fmt"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres/sqlcgen"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// AssetPosition is where a page ended: the sort key of its last Asset.
type AssetPosition struct {
	Name string
	Ref  inventory.SourceReference
}

// AssetListQuery selects one page of a Customer's Assets, sorted by name,
// then CMDB Source, then Record ID.
type AssetListQuery struct {
	Customer tenancy.CustomerID
	// Active keeps only Active Assets when true and only Inactive ones when
	// false; nil keeps both.
	Active      *bool
	Kind        *inventory.AssetKind
	Criticality *inventory.Criticality
	// After, when set, starts the page just past that position.
	After *AssetPosition
	Limit int
}

// AssetPage is one page of ListAssets.
type AssetPage struct {
	Assets []StoredAsset
	// More is whether Assets past this page match the query.
	More bool
	// Total counts every matching Asset, ignoring After and Limit.
	Total int
}

// ListAssets reads a page of the Customer's Assets across all its CMDB
// Sources, Disconnected ones included, with their Software Components loaded
// in one further query whatever the page size.
func (t *Tx) ListAssets(ctx context.Context, q AssetListQuery) (AssetPage, error) {
	filter := sqlcgen.CountCustomerAssetsParams{CustomerID: uuid.UUID(q.Customer), Active: q.Active}
	if q.Kind != nil {
		filter.KindID = ptr(int16(*q.Kind))
	}
	if q.Criticality != nil {
		filter.CriticalityID = ptr(int16(*q.Criticality))
	}
	total, err := t.q.CountCustomerAssets(ctx, filter)
	if err != nil {
		return AssetPage{}, fmt.Errorf("count assets of customer %s: %w", q.Customer, err)
	}
	params := sqlcgen.ListCustomerAssetsParams{
		CustomerID: filter.CustomerID, Active: filter.Active, KindID: filter.KindID, CriticalityID: filter.CriticalityID,
		// One extra row tells whether another page follows.
		PageSize: int32(q.Limit + 1),
	}
	if after := q.After; after != nil {
		params.AfterName = &after.Name
		params.AfterSourceID = pgtype.UUID{Bytes: after.Ref.Source, Valid: true}
		params.AfterRecordID = &after.Ref.RecordID
	}
	rows, err := t.q.ListCustomerAssets(ctx, params)
	if err != nil {
		return AssetPage{}, fmt.Errorf("list assets of customer %s: %w", q.Customer, err)
	}
	page := AssetPage{Total: int(total)}
	if len(rows) > q.Limit {
		page.More = true
		rows = rows[:q.Limit]
	}
	software, err := t.softwareOf(ctx, rows)
	if err != nil {
		return AssetPage{}, err
	}
	page.Assets = make([]StoredAsset, len(rows))
	for i, row := range rows {
		if page.Assets[i], err = restoreAsset(sqlcgen.ListAssetsRow(row), software); err != nil {
			return AssetPage{}, err
		}
	}
	return page, nil
}

func (t *Tx) softwareOf(ctx context.Context, rows []sqlcgen.ListCustomerAssetsRow) (map[inventory.SourceReference][]inventory.SoftwareComponent, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	sources := make([]uuid.UUID, len(rows))
	records := make([]string, len(rows))
	for i, row := range rows {
		sources[i], records[i] = row.CmdbSourceID, row.RecordID
	}
	components, err := t.q.ListSoftwareComponentsOf(ctx, sqlcgen.ListSoftwareComponentsOfParams{SourceIds: sources, RecordIds: records})
	if err != nil {
		return nil, fmt.Errorf("list software of %d assets: %w", len(rows), err)
	}
	return softwareByAsset(components), nil
}

func ptr[T any](v T) *T { return &v }
