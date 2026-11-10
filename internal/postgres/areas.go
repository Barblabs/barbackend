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

func (t *sourceTx) areas(ctx context.Context) ([]*inventory.Area, error) {
	rows, err := t.q.ListAreas(ctx, uuid.UUID(t.source))
	if err != nil {
		return nil, fmt.Errorf("list areas of %s: %w", t.source, err)
	}
	areas := make([]*inventory.Area, len(rows))
	for i, row := range rows {
		ref := inventory.SourceReference{Source: t.source, RecordID: row.RecordID}
		if areas[i], err = restoreArea(ref, row); err != nil {
			return nil, fmt.Errorf("restore area %v: %w", ref, err)
		}
	}
	return areas, nil
}

func restoreArea(ref inventory.SourceReference, row sqlcgen.ListAreasRow) (*inventory.Area, error) {
	owner, err := ownerEmail(row.OwnerEmail)
	if err != nil {
		return nil, err
	}
	active := row.InactiveSince == nil
	// The source's own status is not stored: Reconcile only folds it into
	// Active and replaces it on every Sync, so the stored state stands in.
	imported, err := inventory.NewImportedArea(inventory.ImportedAreaParams{Name: row.Name, Inactive: !active})
	if err != nil {
		return nil, err
	}
	return inventory.RestoreArea(ref, imported, inventory.AreaState{Active: active, Owner: owner})
}

// saveAreas never writes owner_email: only a Customer Admin states it.
func (t *sourceTx) saveAreas(ctx context.Context, changes inventory.AreaChanges) error {
	if err := t.insertAreas(ctx, changes.Created); err != nil {
		return err
	}
	if err := t.renameAreas(ctx, changes.Renamed); err != nil {
		return err
	}
	source := uuid.UUID(t.source)
	if ids := recordIDs(changes.Deactivated); len(ids) > 0 {
		n, err := t.q.DeactivateAreas(ctx, sqlcgen.DeactivateAreasParams{CmdbSourceID: source, RecordIds: ids})
		if err := t.allUpdated("deactivate areas", len(ids), n, err); err != nil {
			return err
		}
	}
	if ids := recordIDs(changes.Reactivated); len(ids) > 0 {
		n, err := t.q.ReactivateAreas(ctx, sqlcgen.ReactivateAreasParams{CmdbSourceID: source, RecordIds: ids})
		if err := t.allUpdated("reactivate areas", len(ids), n, err); err != nil {
			return err
		}
	}
	return nil
}

func (t *sourceTx) insertAreas(ctx context.Context, created []*inventory.Area) error {
	if len(created) == 0 {
		return nil
	}
	anyInactive := false
	for _, a := range created {
		anyInactive = anyInactive || !a.Active()
	}
	inactiveSince, err := t.inactiveSince(ctx, anyInactive)
	if err != nil {
		return err
	}
	rows := make([]sqlcgen.InsertAreasParams, len(created))
	for i, a := range created {
		rows[i] = sqlcgen.InsertAreasParams{
			CmdbSourceID: uuid.UUID(t.source),
			RecordID:     a.Ref().RecordID,
			Name:         a.Imported().Name(),
		}
		if !a.Active() {
			rows[i].InactiveSince = inactiveSince
		}
	}
	if _, err := t.q.InsertAreas(ctx, rows); err != nil {
		return fmt.Errorf("insert areas of %s: %w", t.source, err)
	}
	return nil
}

func (t *sourceTx) renameAreas(ctx context.Context, renamed []*inventory.Area) error {
	if len(renamed) == 0 {
		return nil
	}
	rows := make([]sqlcgen.RenameAreasParams, len(renamed))
	for i, a := range renamed {
		rows[i] = sqlcgen.RenameAreasParams{
			CmdbSourceID: uuid.UUID(t.source),
			RecordID:     a.Ref().RecordID,
			Name:         a.Imported().Name(),
		}
	}
	var err error
	t.q.RenameAreas(ctx, rows).QueryRow(func(i int, _ string, rowErr error) {
		if err != nil || rowErr == nil {
			return
		}
		ref := renamed[i].Ref()
		if errors.Is(rowErr, pgx.ErrNoRows) {
			err = fmt.Errorf("area %v: %w", ref, ErrNotFound)
		} else {
			err = fmt.Errorf("rename area %v: %w", ref, rowErr)
		}
	})
	return err
}

// inactiveSince is the transaction time, the same time the column defaults
// and now() use, read only when some row is created Inactive. COPY cannot call
// now() itself.
func (t *sourceTx) inactiveSince(ctx context.Context, needed bool) (*time.Time, error) {
	if !needed {
		return nil, nil
	}
	now, err := t.q.TransactionTime(ctx)
	if err != nil {
		return nil, fmt.Errorf("read transaction time: %w", err)
	}
	return &now, nil
}
