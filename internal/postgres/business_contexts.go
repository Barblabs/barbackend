package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"barbackend/internal/business"
	"barbackend/internal/postgres/sqlcgen"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const businessContextKey = "business_contexts_pkey"

// StoredBusinessContext is one version of a Customer's Business Context.
type StoredBusinessContext struct {
	Context business.Context
	// Version counts the saves from 1. It is 0, with the zero Context, for a
	// Customer that has never saved one.
	Version int
	// SavedBy is the email of the User who saved it.
	SavedBy string
	Saved   time.Time
}

// BusinessContext is the newest version of the Customer's Business Context.
func (t *Tx) BusinessContext(ctx context.Context, customer tenancy.CustomerID) (StoredBusinessContext, error) {
	row, err := t.q.GetBusinessContext(ctx, uuid.UUID(customer))
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredBusinessContext{}, nil
	}
	if err != nil {
		return StoredBusinessContext{}, fmt.Errorf("get business context of %s: %w", customer, err)
	}
	if row.Schema != business.Schema {
		return StoredBusinessContext{}, fmt.Errorf("business context %d of %s has schema %q, not %q", row.Version, customer, row.Schema, business.Schema)
	}
	var f business.Fields
	if err := json.Unmarshal(row.Content, &f); err != nil {
		return StoredBusinessContext{}, fmt.Errorf("read business context %d of %s: %w", row.Version, customer, err)
	}
	c, err := business.New(f)
	if err != nil {
		return StoredBusinessContext{}, fmt.Errorf("restore business context %d of %s: %w", row.Version, customer, err)
	}
	return StoredBusinessContext{Context: c, Version: int(row.Version), SavedBy: row.SavedBy, Saved: row.SavedAt}, nil
}

// SaveBusinessContext stores c as the version after base, saved by u. It
// fails with business.ErrStale when base is not the newest version, including
// when another save of the same base commits first.
func (t *Tx) SaveBusinessContext(ctx context.Context, customer tenancy.CustomerID, base int, c business.Context, u tenancy.User) (StoredBusinessContext, error) {
	newest, err := t.q.NewestBusinessContextVersion(ctx, uuid.UUID(customer))
	if err != nil {
		return StoredBusinessContext{}, fmt.Errorf("get newest business context of %s: %w", customer, err)
	}
	if int(newest) != base {
		return StoredBusinessContext{}, fmt.Errorf("save business context of %s on version %d, newest is %d: %w", customer, base, newest, business.ErrStale)
	}
	content, err := json.Marshal(c.Fields())
	if err != nil {
		return StoredBusinessContext{}, fmt.Errorf("write business context of %s: %w", customer, err)
	}
	saved, err := t.q.InsertBusinessContext(ctx, sqlcgen.InsertBusinessContextParams{
		CustomerID: uuid.UUID(customer),
		Version:    newest + 1,
		Schema:     business.Schema,
		Content:    content,
		SavedBy:    uuid.UUID(u.ID()),
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation && pgErr.ConstraintName == businessContextKey {
		return StoredBusinessContext{}, fmt.Errorf("save business context of %s on version %d: %w", customer, base, business.ErrStale)
	}
	if err != nil {
		return StoredBusinessContext{}, fmt.Errorf("insert business context of %s: %w", customer, err)
	}
	return StoredBusinessContext{Context: c, Version: base + 1, SavedBy: u.Email(), Saved: saved}, nil
}
