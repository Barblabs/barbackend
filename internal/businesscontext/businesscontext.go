// Package businesscontext holds the use cases on a Customer's Business
// Context: reading it, as data or as a brief, and saving a new version of it
// (ADR 0017).
package businesscontext

import (
	"context"

	"barbackend/internal/business"
	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
)

type Stored = postgres.StoredBusinessContext

type Service struct {
	db *postgres.DB
}

func New(db *postgres.DB) *Service {
	return &Service{db: db}
}

// Get is the newest version of the caller's Customer's Business Context,
// version 0 when it has never saved one. Every User of the Customer reads it.
func (s *Service) Get(ctx context.Context, caller tenancy.User) (Stored, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return Stored{}, err
	}
	return postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) (Stored, error) {
		return tx.BusinessContext(ctx, customer)
	})
}

// Brief is the newest version as Markdown, headed by the Customer's name,
// with the version it is.
func (s *Service) Brief(ctx context.Context, caller tenancy.User) (string, int, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return "", 0, err
	}
	var (
		stored Stored
		name   string
	)
	err = s.db.InTx(ctx, func(tx *postgres.Tx) error {
		c, err := tx.Customer(ctx, customer)
		if err != nil {
			return err
		}
		name = c.Customer.Name()
		stored, err = tx.BusinessContext(ctx, customer)
		return err
	})
	if err != nil {
		return "", 0, err
	}
	return stored.Context.Brief(name), stored.Version, nil
}

// Save stores f as the version after base, the version the caller read. Only
// a Customer Admin saves. It fails with business.ErrInvalidContext, and with
// business.ErrStale when base is no longer the newest version.
func (s *Service) Save(ctx context.Context, caller tenancy.User, base int, f business.Fields) (Stored, error) {
	customer, err := caller.EditBusinessContext()
	if err != nil {
		return Stored{}, err
	}
	c, err := business.New(f)
	if err != nil {
		return Stored{}, err
	}
	return postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) (Stored, error) {
		return tx.SaveBusinessContext(ctx, customer, base, c, caller)
	})
}
