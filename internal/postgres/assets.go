package postgres

import (
	"context"
	"fmt"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres/sqlcgen"
	"github.com/google/uuid"
)

// CreateAsset stores a new Asset with its imported values, state and Declarations.
func (t *Tx) CreateAsset(ctx context.Context, a *inventory.Asset) error {
	source := uuid.UUID(a.Ref().Source)
	imported, err := t.importedColumns(ctx, source, a.Imported())
	if err != nil {
		return err
	}
	declaredOwner, err := t.declaredOwnerID(ctx, source, a)
	if err != nil {
		return err
	}
	err = t.q.InsertAsset(ctx, sqlcgen.InsertAssetParams{
		CmdbSourceID:       source,
		RecordID:           a.Ref().RecordID,
		Name:               imported.Name,
		Description:        imported.Description,
		KindID:             imported.KindID,
		HardwareVendor:     imported.HardwareVendor,
		HardwareModel:      imported.HardwareModel,
		CriticalityID:      imported.CriticalityID,
		ImportedOwnerID:    imported.ImportedOwnerID,
		Retired:            imported.Retired,
		DeclaredOwnerID:    declaredOwner,
		DeclaredExposureID: nullableID(a.Exposure(), inventory.ExposureUnknown),
		Active:             a.Active(),
	})
	if err != nil {
		return fmt.Errorf("insert asset %v: %w", a.Ref(), err)
	}
	return t.insertSoftware(ctx, source, a.Ref().RecordID, a.Imported().Software())
}

// UpdateImported replaces an existing Asset's imported values; its state and
// Declarations are left as stored.
func (t *Tx) UpdateImported(ctx context.Context, a *inventory.Asset) error {
	source := uuid.UUID(a.Ref().Source)
	imported, err := t.importedColumns(ctx, source, a.Imported())
	if err != nil {
		return err
	}
	imported.CmdbSourceID = source
	imported.RecordID = a.Ref().RecordID
	rows, err := t.q.UpdateAssetImported(ctx, imported)
	if err != nil {
		return fmt.Errorf("update asset %v: %w", a.Ref(), err)
	}
	if rows == 0 {
		return fmt.Errorf("asset %v: %w", a.Ref(), ErrNotFound)
	}
	if err := t.q.DeleteSoftwareComponents(ctx, sqlcgen.DeleteSoftwareComponentsParams{CmdbSourceID: source, RecordID: a.Ref().RecordID}); err != nil {
		return fmt.Errorf("delete software of asset %v: %w", a.Ref(), err)
	}
	return t.insertSoftware(ctx, source, a.Ref().RecordID, a.Imported().Software())
}

// UpdateActive stores whether an existing Asset is Active.
func (t *Tx) UpdateActive(ctx context.Context, a *inventory.Asset) error {
	source := uuid.UUID(a.Ref().Source)
	rows, err := t.q.UpdateAssetActive(ctx, sqlcgen.UpdateAssetActiveParams{
		CmdbSourceID: source,
		RecordID:     a.Ref().RecordID,
		Active:       a.Active(),
	})
	if err != nil {
		return fmt.Errorf("update asset %v: %w", a.Ref(), err)
	}
	if rows == 0 {
		return fmt.Errorf("asset %v: %w", a.Ref(), ErrNotFound)
	}
	return nil
}

// Assets returns every Asset of a CMDB Source, Active or not, ordered by record id.
func (t *Tx) Assets(ctx context.Context, id inventory.CMDBSourceID) ([]*inventory.Asset, error) {
	source := uuid.UUID(id)
	rows, err := t.q.ListAssets(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("list assets of %s: %w", id, err)
	}
	software, err := t.software(ctx, source)
	if err != nil {
		return nil, err
	}
	assets := make([]*inventory.Asset, 0, len(rows))
	for _, row := range rows {
		ref := inventory.SourceReference{Source: id, RecordID: row.RecordID}
		a, err := restoreAsset(ref, row, software[row.RecordID])
		if err != nil {
			return nil, fmt.Errorf("restore asset %v: %w", ref, err)
		}
		assets = append(assets, a)
	}
	return assets, nil
}

func restoreAsset(ref inventory.SourceReference, row sqlcgen.ListAssetsRow, software []inventory.SoftwareComponent) (*inventory.Asset, error) {
	p := inventory.ImportedAssetParams{
		Name:        row.Name,
		Description: row.Description,
		Kind:        inventory.AssetKind(row.KindID),
		Software:    software,
		Criticality: inventory.Criticality(valueOrZero(row.CriticalityID)),
		Owner:       inventory.OwnerEmail(valueOrZero(row.ImportedOwner)),
		Retired:     row.Retired,
	}
	if row.HardwareVendor != nil && row.HardwareModel != nil {
		p.Hardware = &inventory.Hardware{Vendor: *row.HardwareVendor, Model: *row.HardwareModel}
	}
	imported, err := inventory.NewImportedAsset(p)
	if err != nil {
		return nil, err
	}
	return inventory.RestoreAsset(ref, imported, inventory.AssetState{
		Active:           row.Active,
		DeclaredOwner:    inventory.OwnerEmail(valueOrZero(row.DeclaredOwner)),
		DeclaredExposure: inventory.Exposure(valueOrZero(row.DeclaredExposureID)),
	})
}

func (t *Tx) software(ctx context.Context, source uuid.UUID) (map[string][]inventory.SoftwareComponent, error) {
	rows, err := t.q.ListSoftwareComponents(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("list software of %s: %w", source, err)
	}
	byRecord := make(map[string][]inventory.SoftwareComponent)
	for _, row := range rows {
		c := inventory.SoftwareComponent{
			Role:    inventory.SoftwareRole(row.RoleID),
			Name:    row.Name,
			Version: row.Version,
		}
		if row.ProductVendor != nil && row.ProductName != nil {
			c.Product = &inventory.Product{Vendor: *row.ProductVendor, Name: *row.ProductName}
		}
		byRecord[row.RecordID] = append(byRecord[row.RecordID], c)
	}
	return byRecord, nil
}

func (t *Tx) insertSoftware(ctx context.Context, source uuid.UUID, recordID string, software []inventory.SoftwareComponent) error {
	rows := make([]sqlcgen.InsertSoftwareComponentsParams, len(software))
	for i, c := range software {
		rows[i] = sqlcgen.InsertSoftwareComponentsParams{
			CmdbSourceID: source,
			RecordID:     recordID,
			Position:     int16(i),
			RoleID:       int16(c.Role),
			Name:         c.Name,
			Version:      c.Version,
		}
		if c.Product != nil {
			rows[i].ProductVendor = &c.Product.Vendor
			rows[i].ProductName = &c.Product.Name
		}
	}
	if _, err := t.q.InsertSoftwareComponents(ctx, rows); err != nil {
		return fmt.Errorf("insert software of asset %s: %w", recordID, err)
	}
	return nil
}

// importedColumns fills the imported columns shared by insert and update,
// creating the imported Asset Owner if it does not exist yet.
func (t *Tx) importedColumns(ctx context.Context, source uuid.UUID, imported inventory.ImportedAsset) (sqlcgen.UpdateAssetImportedParams, error) {
	p := sqlcgen.UpdateAssetImportedParams{
		Name:          imported.Name(),
		Description:   imported.Description(),
		KindID:        int16(imported.Kind()),
		CriticalityID: nullableID(imported.Criticality(), inventory.CriticalityUnknown),
		Retired:       imported.Retired(),
	}
	if hw, ok := imported.Hardware(); ok {
		p.HardwareVendor, p.HardwareModel = &hw.Vendor, &hw.Model
	}
	if owner, ok := imported.Owner(); ok {
		id, err := t.ownerID(ctx, source, owner)
		if err != nil {
			return p, err
		}
		p.ImportedOwnerID = &id
	}
	return p, nil
}

func (t *Tx) declaredOwnerID(ctx context.Context, source uuid.UUID, a *inventory.Asset) (*int64, error) {
	owner, ok := a.DeclaredOwner()
	if !ok {
		return nil, nil
	}
	id, err := t.ownerID(ctx, source, owner)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func (t *Tx) ownerID(ctx context.Context, source uuid.UUID, email inventory.OwnerEmail) (int64, error) {
	id, err := t.q.UpsertAssetOwner(ctx, sqlcgen.UpsertAssetOwnerParams{CmdbSourceID: source, Email: string(email)})
	if err != nil {
		return 0, fmt.Errorf("upsert asset owner %s: %w", email, err)
	}
	return id, nil
}

// nullableID stores a catalog value, or NULL for the value meaning unknown or undeclared (ADR 0006).
func nullableID[T ~int](v, unset T) *int16 {
	if v == unset {
		return nil
	}
	id := int16(v)
	return &id
}

func valueOrZero[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
