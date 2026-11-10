package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres/sqlcgen"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AreaSummary names an Area where it is shown beside something else.
type AreaSummary struct {
	ID   int64
	Name string
}

// StoredArea is an Area with what only the database records about it.
type StoredArea struct {
	// ID identifies the Area across CMDB Sources, for the HTTP API.
	ID   int64
	Area *inventory.Area
	// InactiveSince is when the Area became Inactive, nil while it is Active.
	InactiveSince *time.Time
}

// ListAreas reads the Customer's Areas across all its CMDB Sources,
// Disconnected ones included, sorted by name, then id. Active keeps only
// Active Areas when true and only Inactive ones when false; nil keeps both.
func (t *Tx) ListAreas(ctx context.Context, customer tenancy.CustomerID, active *bool) ([]StoredArea, error) {
	rows, err := t.q.ListCustomerAreas(ctx, sqlcgen.ListCustomerAreasParams{CustomerID: uuid.UUID(customer), Active: active})
	if err != nil {
		return nil, fmt.Errorf("list areas of customer %s: %w", customer, err)
	}
	areas := make([]StoredArea, len(rows))
	for i, row := range rows {
		if areas[i], err = storedArea(sqlcgen.SetAreaOwnerRow(row)); err != nil {
			return nil, err
		}
	}
	return areas, nil
}

// SetAreaOwner states the owner of the Customer's Area with id; the zero
// OwnerEmail clears it. It fails with ErrNotFound when the Customer has no
// such Area.
func (t *Tx) SetAreaOwner(ctx context.Context, customer tenancy.CustomerID, id int64, owner inventory.OwnerEmail) (StoredArea, error) {
	var email *string
	if owner != (inventory.OwnerEmail{}) {
		email = new(owner.String())
	}
	row, err := t.q.SetAreaOwner(ctx, sqlcgen.SetAreaOwnerParams{OwnerEmail: email, ID: id, CustomerID: uuid.UUID(customer)})
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredArea{}, fmt.Errorf("area %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return StoredArea{}, fmt.Errorf("set owner of area %d: %w", id, err)
	}
	return storedArea(row)
}

func storedArea(row sqlcgen.SetAreaOwnerRow) (StoredArea, error) {
	ref := inventory.SourceReference{Source: inventory.CMDBSourceID(row.CmdbSourceID), RecordID: row.RecordID}
	a, err := restoreArea(ref, row.Name, row.OwnerEmail, row.InactiveSince)
	if err != nil {
		return StoredArea{}, fmt.Errorf("restore area %v: %w", ref, err)
	}
	return StoredArea{ID: row.ID, Area: a, InactiveSince: row.InactiveSince}, nil
}

func (t *sourceTx) areas(ctx context.Context) ([]*inventory.Area, error) {
	rows, err := t.q.ListAreas(ctx, uuid.UUID(t.source))
	if err != nil {
		return nil, fmt.Errorf("list areas of %s: %w", t.source, err)
	}
	areas := make([]*inventory.Area, len(rows))
	for i, row := range rows {
		ref := inventory.SourceReference{Source: t.source, RecordID: row.RecordID}
		if areas[i], err = restoreArea(ref, row.Name, row.OwnerEmail, row.InactiveSince); err != nil {
			return nil, fmt.Errorf("restore area %v: %w", ref, err)
		}
	}
	return areas, nil
}

func restoreArea(ref inventory.SourceReference, name string, email *string, inactiveSince *time.Time) (*inventory.Area, error) {
	owner, err := ownerEmail(email)
	if err != nil {
		return nil, err
	}
	return inventory.RestoreArea(ref, name, inventory.AreaState{Active: inactiveSince == nil, Owner: owner})
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
			Name:         a.Name(),
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
			Name:         a.Name(),
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
