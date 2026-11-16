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

// AssetFilter selects the Assets of a listing. Each filter combines with the
// others by AND; a nil filter keeps every value.
type AssetFilter struct {
	// Active keeps only Active Assets when true and only Inactive ones when
	// false.
	Active *bool
	// Kind, Criticality and Exposure keep the Assets with any of their
	// values. CriticalityUnknown and ExposureUnknown keep the Assets without
	// one. Exposure is the effective one: the declared Exposure, otherwise
	// the imported one.
	Kind        []inventory.AssetKind
	Criticality []inventory.Criticality
	Exposure    []inventory.Exposure
	// InformationClassification keeps the Assets with any of its values, which
	// is only ever declared (ADR 0031), so Unclassified keeps the Assets
	// without a Declaration.
	InformationClassification []inventory.InformationClassification
	// Lifecycle keeps the Assets with any of its stages. LifecycleUnknown
	// keeps the Assets without one, which includes every retired Asset
	// (ADR 0028).
	Lifecycle []inventory.LifecycleStage
	// Area keeps the Assets in any of the Areas with those ids, as GET /areas
	// returns them. An id that is not one of the Customer's Areas matches no
	// Asset.
	Area []int64
}

// AssetListQuery selects one page of a Customer's Assets, sorted by name,
// then CMDB Source, then Record ID.
type AssetListQuery struct {
	Customer tenancy.CustomerID
	Filter   AssetFilter
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
	params := sqlcgen.ListCustomerAssetsParams{
		CustomerID: uuid.UUID(q.Customer), Active: q.Filter.Active,
		KindIds:                      catalogIDs(q.Filter.Kind),
		CriticalityIds:               catalogIDs(q.Filter.Criticality),
		ExposureIds:                  catalogIDs(q.Filter.Exposure),
		InformationClassificationIds: catalogIDs(q.Filter.InformationClassification),
		LifecycleStageIds:            catalogIDs(q.Filter.Lifecycle),
		AreaIds:                      areaIDs(q.Filter.Area),
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
	// total rides every matching row, counted before the page keyset narrows
	// them; no rows means no match, so a total of zero.
	page := AssetPage{}
	if len(rows) > 0 {
		page.Total = int(rows[0].Total)
	}
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
		if page.Assets[i], err = restoreAsset(assetRow(row), software); err != nil {
			return AssetPage{}, err
		}
	}
	return page, nil
}

// assetRow drops the window total so a listed row restores as ListAssets reads
// it.
func assetRow(row sqlcgen.ListCustomerAssetsRow) sqlcgen.ListAssetsRow {
	return sqlcgen.ListAssetsRow{
		ID: row.ID, CmdbSourceID: row.CmdbSourceID, RecordID: row.RecordID,
		Name: row.Name, Description: row.Description, KindID: row.KindID,
		HardwareVendor: row.HardwareVendor, HardwareModel: row.HardwareModel, CriticalityID: row.CriticalityID,
		ImportedOwner: row.ImportedOwner, DeclaredOwner: row.DeclaredOwner,
		ImportedExposureID: row.ImportedExposureID, DeclaredExposureID: row.DeclaredExposureID,
		LifecycleStageID: row.LifecycleStageID, AreaRecordID: row.AreaRecordID,
		Retired: row.Retired, InactiveSince: row.InactiveSince,
		AreaID: row.AreaID, AreaName: row.AreaName,
		ExposureDeclaredBy: row.ExposureDeclaredBy, ExposureDeclaredAt: row.ExposureDeclaredAt,
		DeclaredInformationClassificationID: row.DeclaredInformationClassificationID,
		InformationClassificationDeclaredBy: row.InformationClassificationDeclaredBy,
		InformationClassificationDeclaredAt: row.InformationClassificationDeclaredAt,
	}
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

// catalogIDs is never nil: pgx sends a nil slice as NULL, whose cardinality
// is NULL rather than 0, so it would match no Asset instead of every one.
func catalogIDs[T ~int](values []T) []int16 {
	ids := make([]int16, 0, len(values))
	for _, v := range values {
		ids = append(ids, int16(v))
	}
	return ids
}

// areaIDs is never nil, for the reason catalogIDs is not: a nil slice reaches
// pgx as NULL, whose cardinality is NULL rather than 0.
func areaIDs(values []int64) []int64 {
	ids := make([]int64, 0, len(values))
	return append(ids, values...)
}

func ptr[T any](v T) *T { return &v }
