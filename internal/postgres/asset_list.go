package postgres

import (
	"context"
	"fmt"
	"time"

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

// OwnerValue is the effective Asset Owner and where it comes from.
type OwnerValue struct {
	Email    inventory.OwnerEmail
	Declared bool
}

// ListedAsset is an Asset as a list shows it: the imported values and the
// effective Declarations, without the bookkeeping columns.
type ListedAsset struct {
	Ref         inventory.SourceReference
	Name        string
	Description string
	Kind        inventory.AssetKind
	// Hardware is nil for an Asset without any.
	Hardware    *inventory.Hardware
	Software    []inventory.SoftwareComponent
	Criticality inventory.Criticality
	Exposure    inventory.Exposure
	// Owner is nil when the Asset has neither a declared nor an imported owner.
	Owner         *OwnerValue
	Retired       bool
	InactiveSince *time.Time
}

// AssetPage is one page of ListAssets.
type AssetPage struct {
	Assets []ListedAsset
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
	page.Assets = make([]ListedAsset, len(rows))
	for i, row := range rows {
		ref := inventory.SourceReference{Source: inventory.CMDBSourceID(row.CmdbSourceID), RecordID: row.RecordID}
		page.Assets[i], err = listedAsset(ref, row, software[ref])
		if err != nil {
			return AssetPage{}, fmt.Errorf("restore asset %v: %w", ref, err)
		}
	}
	return page, nil
}

func listedAsset(ref inventory.SourceReference, row sqlcgen.ListCustomerAssetsRow, software []inventory.SoftwareComponent) (ListedAsset, error) {
	a := ListedAsset{
		Ref:           ref,
		Name:          row.Name,
		Description:   row.Description,
		Kind:          inventory.AssetKind(row.KindID),
		Software:      software,
		Criticality:   inventory.Criticality(valueOrZero(row.CriticalityID)),
		Exposure:      inventory.Exposure(valueOrZero(row.DeclaredExposureID)),
		Retired:       row.Retired,
		InactiveSince: row.InactiveSince,
	}
	if row.HardwareVendor != nil {
		a.Hardware = &inventory.Hardware{Vendor: *row.HardwareVendor, Model: valueOrZero(row.HardwareModel)}
	}
	// The Declaration wins over the imported value (ADR 0004).
	email, declared := row.DeclaredOwner, true
	if email == nil {
		email, declared = row.ImportedOwner, false
	}
	if email != nil {
		owner, err := inventory.NewOwnerEmail(*email)
		if err != nil {
			return ListedAsset{}, err
		}
		a.Owner = &OwnerValue{Email: owner, Declared: declared}
	}
	return a, nil
}

func (t *Tx) softwareOf(ctx context.Context, rows []sqlcgen.ListCustomerAssetsRow) (map[inventory.SourceReference][]inventory.SoftwareComponent, error) {
	byAsset := make(map[inventory.SourceReference][]inventory.SoftwareComponent, len(rows))
	if len(rows) == 0 {
		return byAsset, nil
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
	for _, row := range components {
		ref := inventory.SourceReference{Source: inventory.CMDBSourceID(row.CmdbSourceID), RecordID: row.RecordID}
		byAsset[ref] = append(byAsset[ref], inventory.SoftwareComponent{
			Role:    inventory.SoftwareRole(row.RoleID),
			Name:    row.Name,
			Version: row.Version,
			Product: inventory.Product{Vendor: valueOrZero(row.ProductVendor), Name: valueOrZero(row.ProductName)},
		})
	}
	return byAsset, nil
}

func ptr[T any](v T) *T { return &v }
