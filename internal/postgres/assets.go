package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres/sqlcgen"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type sourceTx struct {
	q      *sqlcgen.Queries
	source inventory.CMDBSourceID
}

func (t *sourceTx) stored(ctx context.Context) (inventory.Stored, error) {
	assets, err := t.assets(ctx)
	if err != nil {
		return inventory.Stored{}, err
	}
	areas, err := t.areas(ctx)
	if err != nil {
		return inventory.Stored{}, err
	}
	return inventory.Stored{Assets: assets, Areas: areas}, nil
}

func (t *sourceTx) assets(ctx context.Context) ([]*inventory.Asset, error) {
	source := uuid.UUID(t.source)
	rows, err := t.q.ListAssets(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("list assets of %s: %w", t.source, err)
	}
	components, err := t.q.ListSoftwareComponents(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("list software of %s: %w", t.source, err)
	}
	software := softwareByAsset(components)
	assets := make([]*inventory.Asset, len(rows))
	for i, row := range rows {
		stored, err := restoreAsset(row, software)
		if err != nil {
			return nil, err
		}
		assets[i] = stored.Asset
	}
	return assets, nil
}

func (t *sourceTx) save(ctx context.Context, r inventory.Reconciliation) error {
	if r.Source() != t.source {
		return fmt.Errorf("save to %s: reconciliation of %s", t.source, r.Source())
	}
	created, updated := r.Created(), r.Updated()
	owners, err := t.upsertOwners(ctx, slices.Concat(created, updated))
	if err != nil {
		return err
	}
	if err := t.saveAreas(ctx, r.Areas()); err != nil {
		return err
	}
	if err := t.insertCreated(ctx, created, owners); err != nil {
		return err
	}
	if err := t.updateImported(ctx, updated, owners); err != nil {
		return err
	}
	if err := t.replaceSoftware(ctx, created, updated); err != nil {
		return err
	}
	return t.updateActive(ctx, r.Deactivated(), r.Reactivated())
}

type ownerIDs map[string]int64

func (ids ownerIDs) ref(owner inventory.OwnerEmail, ok bool) *int64 {
	if !ok {
		return nil
	}
	id := ids[owner.String()]
	return &id
}

func (t *sourceTx) upsertOwners(ctx context.Context, written []*inventory.Asset) (ownerIDs, error) {
	seen := map[string]bool{}
	var emails []string
	add := func(owner inventory.OwnerEmail, ok bool) {
		if ok && !seen[owner.String()] {
			seen[owner.String()] = true
			emails = append(emails, owner.String())
		}
	}
	for _, a := range written {
		add(a.Imported().Owner())
	}
	if len(emails) == 0 {
		return nil, nil
	}
	rows, err := t.q.UpsertAssetOwners(ctx, sqlcgen.UpsertAssetOwnersParams{CmdbSourceID: uuid.UUID(t.source), Emails: emails})
	if err != nil {
		return nil, fmt.Errorf("upsert asset owners of %s: %w", t.source, err)
	}
	ids := make(ownerIDs, len(rows))
	for _, row := range rows {
		ids[row.Email] = row.ID
	}
	return ids, nil
}

func (t *sourceTx) insertCreated(ctx context.Context, created []*inventory.Asset, owners ownerIDs) error {
	if len(created) == 0 {
		return nil
	}
	inactiveSince, err := createdInactiveSince(ctx, t, created)
	if err != nil {
		return err
	}
	rows := make([]sqlcgen.InsertAssetsParams, len(created))
	for i, a := range created {
		imported := importedColumns(t.source, a, owners)
		rows[i] = sqlcgen.InsertAssetsParams{
			CmdbSourceID:       imported.CmdbSourceID,
			RecordID:           imported.RecordID,
			Name:               imported.Name,
			Description:        imported.Description,
			KindID:             imported.KindID,
			HardwareVendor:     imported.HardwareVendor,
			HardwareModel:      imported.HardwareModel,
			CriticalityID:      imported.CriticalityID,
			ImportedExposureID: imported.ImportedExposureID,
			LifecycleStageID:   imported.LifecycleStageID,
			ImportedOwnerID:    imported.ImportedOwnerID,
			AreaRecordID:       imported.AreaRecordID,
			Retired:            imported.Retired,
		}
		if !a.Active() {
			rows[i].InactiveSince = inactiveSince
		}
	}
	if _, err := t.q.InsertAssets(ctx, rows); err != nil {
		return fmt.Errorf("insert assets of %s: %w", t.source, err)
	}
	return nil
}

func (t *sourceTx) updateImported(ctx context.Context, updated []*inventory.Asset, owners ownerIDs) error {
	if len(updated) == 0 {
		return nil
	}
	rows := make([]sqlcgen.UpdateAssetImportedParams, len(updated))
	for i, a := range updated {
		rows[i] = importedColumns(t.source, a, owners)
	}
	var err error
	t.q.UpdateAssetImported(ctx, rows).QueryRow(func(i int, _ string, rowErr error) {
		if err != nil || rowErr == nil {
			return
		}
		ref := inventory.SourceReference{Source: t.source, RecordID: rows[i].RecordID}
		if errors.Is(rowErr, pgx.ErrNoRows) {
			err = fmt.Errorf("asset %v: %w", ref, ErrNotFound)
		} else {
			err = fmt.Errorf("update asset %v: %w", ref, rowErr)
		}
	})
	return err
}

func (t *sourceTx) replaceSoftware(ctx context.Context, created, updated []*inventory.Asset) error {
	source := uuid.UUID(t.source)
	var rows []sqlcgen.InsertSoftwareComponentsParams
	for _, a := range slices.Concat(created, updated) {
		recordID := a.Ref().RecordID
		for i, sc := range a.Imported().Software() {
			row := sqlcgen.InsertSoftwareComponentsParams{
				CmdbSourceID: source,
				RecordID:     recordID,
				Position:     int16(i),
				RoleID:       int16(sc.Role),
				Name:         sc.Name,
				Version:      sc.Version,
			}
			if sc.Identified() {
				row.ProductVendor, row.ProductName = &sc.Product.Vendor, &sc.Product.Name
			}
			rows = append(rows, row)
		}
	}
	if len(updated) > 0 {
		err := t.q.DeleteSoftwareComponents(ctx, sqlcgen.DeleteSoftwareComponentsParams{CmdbSourceID: source, RecordIds: recordIDs(updated)})
		if err != nil {
			return fmt.Errorf("delete software of %s: %w", t.source, err)
		}
	}
	if len(rows) > 0 {
		if _, err := t.q.InsertSoftwareComponents(ctx, rows); err != nil {
			return fmt.Errorf("insert software of %s: %w", t.source, err)
		}
	}
	return nil
}

func (t *sourceTx) updateActive(ctx context.Context, deactivated, reactivated []*inventory.Asset) error {
	source := uuid.UUID(t.source)
	if len(deactivated) > 0 {
		n, err := t.q.DeactivateAssets(ctx, sqlcgen.DeactivateAssetsParams{CmdbSourceID: source, RecordIds: recordIDs(deactivated)})
		if err := t.allUpdated("deactivate assets", len(deactivated), n, err); err != nil {
			return err
		}
	}
	if len(reactivated) > 0 {
		n, err := t.q.ReactivateAssets(ctx, sqlcgen.ReactivateAssetsParams{CmdbSourceID: source, RecordIds: recordIDs(reactivated)})
		if err := t.allUpdated("reactivate assets", len(reactivated), n, err); err != nil {
			return err
		}
	}
	return nil
}

func (t *sourceTx) allUpdated(action string, want int, updated int64, err error) error {
	if err != nil {
		return fmt.Errorf("%s of %s: %w", action, t.source, err)
	}
	if missing := int64(want) - updated; missing > 0 {
		return fmt.Errorf("%s of %s: %d of %d: %w", action, t.source, missing, want, ErrNotFound)
	}
	return nil
}

type sourceRecord interface {
	Ref() inventory.SourceReference
}

func recordIDs[T sourceRecord](items []T) []string {
	ids := make([]string, len(items))
	for i, item := range items {
		ids[i] = item.Ref().RecordID
	}
	return ids
}

func importedColumns(source inventory.CMDBSourceID, a *inventory.Asset, owners ownerIDs) sqlcgen.UpdateAssetImportedParams {
	imported := a.Imported()
	p := sqlcgen.UpdateAssetImportedParams{
		CmdbSourceID:       uuid.UUID(source),
		RecordID:           a.Ref().RecordID,
		Name:               imported.Name(),
		Description:        imported.Description(),
		KindID:             int16(imported.Kind()),
		CriticalityID:      nullableID(imported.Criticality(), inventory.CriticalityUnknown),
		ImportedExposureID: nullableID(imported.Exposure(), inventory.ExposureUnknown),
		LifecycleStageID:   nullableID(imported.Lifecycle(), inventory.LifecycleUnknown),
		ImportedOwnerID:    owners.ref(imported.Owner()),
		Retired:            imported.Retired(),
	}
	if hw, ok := imported.Hardware(); ok {
		p.HardwareVendor, p.HardwareModel = &hw.Vendor, &hw.Model
	}
	if area, ok := imported.Area(); ok {
		p.AreaRecordID = &area
	}
	return p
}

// StoredAsset is an Asset with what only the database records about it.
type StoredAsset struct {
	// ID is the handle the HTTP API uses for the Asset (ADR 0021).
	ID    int64
	Asset *inventory.Asset
	// Area is the Asset's Area, nil when it has none.
	Area *AreaSummary
	// InactiveSince is when the Asset became Inactive, nil while it is Active.
	InactiveSince *time.Time
	// ExposureAudit is who declared the Asset's Exposure and when, set exactly
	// when Asset.DeclaredExposure is not Unknown.
	ExposureAudit DeclarationAudit
}

// DeclarationAudit is who stated a declared value and when.
type DeclarationAudit struct {
	By string
	At time.Time
}

func restoreAsset(row sqlcgen.ListAssetsRow, software map[inventory.SourceReference][]inventory.SoftwareComponent) (StoredAsset, error) {
	ref := inventory.SourceReference{Source: inventory.CMDBSourceID(row.CmdbSourceID), RecordID: row.RecordID}
	a, err := restoreAssetValues(ref, row, software[ref])
	if err != nil {
		return StoredAsset{}, fmt.Errorf("restore asset %v: %w", ref, err)
	}
	stored := StoredAsset{ID: row.ID, Asset: a, InactiveSince: row.InactiveSince}
	if row.AreaID != nil {
		stored.Area = &AreaSummary{ID: *row.AreaID, Name: valueOrZero(row.AreaName)}
	}
	if row.DeclaredExposureID != nil {
		if row.ExposureDeclaredBy == nil || row.ExposureDeclaredAt == nil {
			return StoredAsset{}, fmt.Errorf("restore asset %v: declared exposure without who declared it and when", ref)
		}
		stored.ExposureAudit = DeclarationAudit{By: *row.ExposureDeclaredBy, At: *row.ExposureDeclaredAt}
	}
	return stored, nil
}

func restoreAssetValues(ref inventory.SourceReference, row sqlcgen.ListAssetsRow, software []inventory.SoftwareComponent) (*inventory.Asset, error) {
	importedOwner, err := ownerEmail(row.ImportedOwner)
	if err != nil {
		return nil, err
	}
	declaredOwner, err := ownerEmail(row.DeclaredOwner)
	if err != nil {
		return nil, err
	}
	imported, err := inventory.NewImportedAsset(inventory.ImportedAssetParams{
		Name:        row.Name,
		Description: row.Description,
		Kind:        inventory.AssetKind(row.KindID),
		Hardware:    inventory.Hardware{Vendor: valueOrZero(row.HardwareVendor), Model: valueOrZero(row.HardwareModel)},
		Software:    software,
		Criticality: inventory.Criticality(valueOrZero(row.CriticalityID)),
		Exposure:    inventory.Exposure(valueOrZero(row.ImportedExposureID)),
		Lifecycle:   inventory.LifecycleStage(valueOrZero(row.LifecycleStageID)),
		Owner:       importedOwner,
		Area:        valueOrZero(row.AreaRecordID),
		Retired:     row.Retired,
	})
	if err != nil {
		return nil, err
	}
	return inventory.RestoreAsset(ref, imported, inventory.AssetState{
		Active:           row.InactiveSince == nil,
		DeclaredOwner:    declaredOwner,
		DeclaredExposure: inventory.Exposure(valueOrZero(row.DeclaredExposureID)),
	})
}

func ownerEmail(email *string) (inventory.OwnerEmail, error) {
	if email == nil {
		return inventory.OwnerEmail{}, nil
	}
	return inventory.NewOwnerEmail(*email)
}

func softwareByAsset(rows []sqlcgen.SoftwareComponent) map[inventory.SourceReference][]inventory.SoftwareComponent {
	byAsset := make(map[inventory.SourceReference][]inventory.SoftwareComponent)
	for _, row := range rows {
		ref := inventory.SourceReference{Source: inventory.CMDBSourceID(row.CmdbSourceID), RecordID: row.RecordID}
		byAsset[ref] = append(byAsset[ref], inventory.SoftwareComponent{
			Role:    inventory.SoftwareRole(row.RoleID),
			Name:    row.Name,
			Version: row.Version,
			Product: inventory.Product{Vendor: valueOrZero(row.ProductVendor), Name: valueOrZero(row.ProductName)},
		})
	}
	return byAsset
}

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
