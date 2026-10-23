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

func (t *sourceTx) assets(ctx context.Context) ([]*inventory.Asset, error) {
	source := uuid.UUID(t.source)
	rows, err := t.q.ListAssets(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("list assets of %s: %w", t.source, err)
	}
	software, err := t.software(ctx)
	if err != nil {
		return nil, err
	}
	assets := make([]*inventory.Asset, 0, len(rows))
	for _, row := range rows {
		ref := inventory.SourceReference{Source: t.source, RecordID: row.RecordID}
		a, err := restoreAsset(ref, row, software[row.RecordID])
		if err != nil {
			return nil, fmt.Errorf("restore asset %v: %w", ref, err)
		}
		assets = append(assets, a)
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
	var inactiveSince *time.Time
	for _, a := range created {
		if !a.Active() {
			now, err := t.q.TransactionTime(ctx)
			if err != nil {
				return fmt.Errorf("read transaction time: %w", err)
			}
			inactiveSince = &now
			break
		}
	}
	rows := make([]sqlcgen.InsertAssetsParams, len(created))
	for i, a := range created {
		imported := importedColumns(t.source, a, owners)
		rows[i] = sqlcgen.InsertAssetsParams{
			CmdbSourceID:    imported.CmdbSourceID,
			RecordID:        imported.RecordID,
			Name:            imported.Name,
			Description:     imported.Description,
			KindID:          imported.KindID,
			HardwareVendor:  imported.HardwareVendor,
			HardwareModel:   imported.HardwareModel,
			CriticalityID:   imported.CriticalityID,
			ImportedOwnerID: imported.ImportedOwnerID,
			Retired:         imported.Retired,
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
		if err := t.allUpdated("deactivate", len(deactivated), n, err); err != nil {
			return err
		}
	}
	if len(reactivated) > 0 {
		n, err := t.q.ReactivateAssets(ctx, sqlcgen.ReactivateAssetsParams{CmdbSourceID: source, RecordIds: recordIDs(reactivated)})
		if err := t.allUpdated("reactivate", len(reactivated), n, err); err != nil {
			return err
		}
	}
	return nil
}

func (t *sourceTx) allUpdated(action string, want int, updated int64, err error) error {
	if err != nil {
		return fmt.Errorf("%s assets of %s: %w", action, t.source, err)
	}
	if missing := int64(want) - updated; missing > 0 {
		return fmt.Errorf("%s assets of %s: %d of %d: %w", action, t.source, missing, want, ErrNotFound)
	}
	return nil
}

func recordIDs(assets []*inventory.Asset) []string {
	ids := make([]string, len(assets))
	for i, a := range assets {
		ids[i] = a.Ref().RecordID
	}
	return ids
}

func importedColumns(source inventory.CMDBSourceID, a *inventory.Asset, owners ownerIDs) sqlcgen.UpdateAssetImportedParams {
	imported := a.Imported()
	p := sqlcgen.UpdateAssetImportedParams{
		CmdbSourceID:    uuid.UUID(source),
		RecordID:        a.Ref().RecordID,
		Name:            imported.Name(),
		Description:     imported.Description(),
		KindID:          int16(imported.Kind()),
		CriticalityID:   nullableID(imported.Criticality(), inventory.CriticalityUnknown),
		ImportedOwnerID: owners.ref(imported.Owner()),
		Retired:         imported.Retired(),
	}
	if hw, ok := imported.Hardware(); ok {
		p.HardwareVendor, p.HardwareModel = &hw.Vendor, &hw.Model
	}
	return p
}

func restoreAsset(ref inventory.SourceReference, row sqlcgen.ListAssetsRow, software []inventory.SoftwareComponent) (*inventory.Asset, error) {
	importedOwner, err := ownerEmail(row.ImportedOwner)
	if err != nil {
		return nil, err
	}
	declaredOwner, err := ownerEmail(row.DeclaredOwner)
	if err != nil {
		return nil, err
	}
	p := inventory.ImportedAssetParams{
		Name:        row.Name,
		Description: row.Description,
		Kind:        inventory.AssetKind(row.KindID),
		Hardware:    inventory.Hardware{Vendor: valueOrZero(row.HardwareVendor), Model: valueOrZero(row.HardwareModel)},
		Software:    software,
		Criticality: inventory.Criticality(valueOrZero(row.CriticalityID)),
		Owner:       importedOwner,
		Retired:     row.Retired,
	}
	imported, err := inventory.NewImportedAsset(p)
	if err != nil {
		return nil, err
	}
	return inventory.RestoreAsset(ref, imported, inventory.AssetState{
		Active:           row.Active,
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

func (t *sourceTx) software(ctx context.Context) (map[string][]inventory.SoftwareComponent, error) {
	rows, err := t.q.ListSoftwareComponents(ctx, uuid.UUID(t.source))
	if err != nil {
		return nil, fmt.Errorf("list software of %s: %w", t.source, err)
	}
	byRecord := make(map[string][]inventory.SoftwareComponent)
	for _, row := range rows {
		c := inventory.SoftwareComponent{
			Role:    inventory.SoftwareRole(row.RoleID),
			Name:    row.Name,
			Version: row.Version,
			Product: inventory.Product{Vendor: valueOrZero(row.ProductVendor), Name: valueOrZero(row.ProductName)},
		}
		byRecord[row.RecordID] = append(byRecord[row.RecordID], c)
	}
	return byRecord, nil
}

func nullableID[T ~int16](v, unset T) *int16 {
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
