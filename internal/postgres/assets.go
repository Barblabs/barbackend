package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres/sqlcgen"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SourceTx reads and writes the Assets of one locked CMDB Source.
type SourceTx struct {
	q      *sqlcgen.Queries
	source inventory.CMDBSourceID
}

// Assets returns every Asset of the CMDB Source, Active or not, ordered by record id.
func (t *SourceTx) Assets(ctx context.Context) ([]*inventory.Asset, error) {
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

// Save writes the changes of a Reconciliation and the successful Sync Run
// that produced it. Updates write only imported values and the Active state,
// so Declarations stay as stored. Each kind of write is one statement for all
// Assets, so a Sync takes the same number of round trips at any size.
func (t *SourceTx) Save(ctx context.Context, r inventory.Reconciliation, run inventory.SyncRun) error {
	switch {
	case r.Source() != t.source || run.Source() != t.source:
		return fmt.Errorf("save to %s: reconciliation of %s, run of %s", t.source, r.Source(), run.Source())
	case run.Outcome() != inventory.SyncSucceeded:
		return fmt.Errorf("save to %s: run outcome is %s", t.source, run.Outcome())
	}
	changes := r.Changes()
	owners, err := t.upsertOwners(ctx, changes)
	if err != nil {
		return err
	}
	if err := t.insertCreated(ctx, changes, owners); err != nil {
		return err
	}
	if err := t.updateImported(ctx, changes, owners); err != nil {
		return err
	}
	if err := t.replaceSoftware(ctx, changes); err != nil {
		return err
	}
	if err := t.updateActive(ctx, changes); err != nil {
		return err
	}
	return recordSyncRun(ctx, t.q, run)
}

// ownerIDs maps an Asset Owner's email to its row id.
type ownerIDs map[string]int64

func (ids ownerIDs) ref(owner inventory.OwnerEmail, ok bool) *int64 {
	if !ok {
		return nil
	}
	id := ids[owner.String()]
	return &id
}

// upsertOwners stores every Asset Owner the changes write. Only created Assets
// write a declared owner: updates keep the stored Declarations.
func (t *SourceTx) upsertOwners(ctx context.Context, changes []inventory.Change) (ownerIDs, error) {
	seen := map[string]bool{}
	var emails []string
	add := func(owner inventory.OwnerEmail, ok bool) {
		if ok && !seen[owner.String()] {
			seen[owner.String()] = true
			emails = append(emails, owner.String())
		}
	}
	for _, c := range changes {
		if c.Created || c.ImportedChanged {
			add(c.Asset.Imported().Owner())
		}
		if c.Created {
			add(c.Asset.DeclaredOwner())
		}
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

func (t *SourceTx) insertCreated(ctx context.Context, changes []inventory.Change, owners ownerIDs) error {
	var created []*inventory.Asset
	for _, c := range changes {
		if c.Created {
			created = append(created, c.Asset)
		}
	}
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
			CmdbSourceID:       imported.CmdbSourceID,
			RecordID:           imported.RecordID,
			Name:               imported.Name,
			Description:        imported.Description,
			KindID:             imported.KindID,
			HardwareVendor:     imported.HardwareVendor,
			HardwareModel:      imported.HardwareModel,
			CriticalityID:      imported.CriticalityID,
			ImportedOwnerID:    imported.ImportedOwnerID,
			Retired:            imported.Retired,
			DeclaredOwnerID:    owners.ref(a.DeclaredOwner()),
			DeclaredExposureID: nullableID(a.Exposure(), inventory.ExposureUnknown),
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

func (t *SourceTx) updateImported(ctx context.Context, changes []inventory.Change, owners ownerIDs) error {
	var rows []sqlcgen.UpdateAssetImportedParams
	for _, c := range changes {
		if c.ImportedChanged {
			rows = append(rows, importedColumns(t.source, c.Asset, owners))
		}
	}
	if len(rows) == 0 {
		return nil
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

// replaceSoftware rewrites the Software Components of every Asset whose
// imported values were written: they have no identity to update in place.
func (t *SourceTx) replaceSoftware(ctx context.Context, changes []inventory.Change) error {
	source := uuid.UUID(t.source)
	var replaced []string
	var rows []sqlcgen.InsertSoftwareComponentsParams
	for _, c := range changes {
		if !c.Created && !c.ImportedChanged {
			continue
		}
		recordID := c.Asset.Ref().RecordID
		if c.ImportedChanged {
			replaced = append(replaced, recordID)
		}
		for i, sc := range c.Asset.Imported().Software() {
			row := sqlcgen.InsertSoftwareComponentsParams{
				CmdbSourceID: source,
				RecordID:     recordID,
				Position:     int16(i),
				RoleID:       int16(sc.Role),
				Name:         sc.Name,
				Version:      sc.Version,
			}
			if sc.Product != nil {
				row.ProductVendor, row.ProductName = &sc.Product.Vendor, &sc.Product.Name
			}
			rows = append(rows, row)
		}
	}
	if len(replaced) > 0 {
		err := t.q.DeleteSoftwareComponents(ctx, sqlcgen.DeleteSoftwareComponentsParams{CmdbSourceID: source, RecordIds: replaced})
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

func (t *SourceTx) updateActive(ctx context.Context, changes []inventory.Change) error {
	var deactivated, reactivated []string
	for _, c := range changes {
		switch {
		case !c.ActiveChanged:
		case c.Asset.Active():
			reactivated = append(reactivated, c.Asset.Ref().RecordID)
		default:
			deactivated = append(deactivated, c.Asset.Ref().RecordID)
		}
	}
	source := uuid.UUID(t.source)
	if len(deactivated) > 0 {
		n, err := t.q.DeactivateAssets(ctx, sqlcgen.DeactivateAssetsParams{CmdbSourceID: source, RecordIds: deactivated})
		if err := t.allUpdated("deactivate", deactivated, n, err); err != nil {
			return err
		}
	}
	if len(reactivated) > 0 {
		n, err := t.q.ReactivateAssets(ctx, sqlcgen.ReactivateAssetsParams{CmdbSourceID: source, RecordIds: reactivated})
		if err := t.allUpdated("reactivate", reactivated, n, err); err != nil {
			return err
		}
	}
	return nil
}

func (t *SourceTx) allUpdated(action string, recordIDs []string, updated int64, err error) error {
	if err != nil {
		return fmt.Errorf("%s assets of %s: %w", action, t.source, err)
	}
	if missing := int64(len(recordIDs)) - updated; missing > 0 {
		return fmt.Errorf("%s assets of %s: %d of %d: %w", action, t.source, missing, len(recordIDs), ErrNotFound)
	}
	return nil
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
		Software:    software,
		Criticality: inventory.Criticality(valueOrZero(row.CriticalityID)),
		Owner:       importedOwner,
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
		DeclaredOwner:    declaredOwner,
		DeclaredExposure: inventory.Exposure(valueOrZero(row.DeclaredExposureID)),
	})
}

// ownerEmail maps a nullable email column; NULL is the zero OwnerEmail, meaning no owner.
func ownerEmail(email *string) (inventory.OwnerEmail, error) {
	if email == nil {
		return inventory.OwnerEmail{}, nil
	}
	return inventory.NewOwnerEmail(*email)
}

func (t *SourceTx) software(ctx context.Context) (map[string][]inventory.SoftwareComponent, error) {
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
		}
		if row.ProductVendor != nil && row.ProductName != nil {
			c.Product = &inventory.Product{Vendor: *row.ProductVendor, Name: *row.ProductName}
		}
		byRecord[row.RecordID] = append(byRecord[row.RecordID], c)
	}
	return byRecord, nil
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
