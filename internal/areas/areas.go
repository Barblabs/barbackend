// Package areas holds the use cases on a Customer's Areas: listing them
// across all its CMDB Sources (ADR 0008).
package areas

import (
	"context"

	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
)

type StoredArea = postgres.StoredArea

type Service struct {
	db *postgres.DB
}

func New(db *postgres.DB) *Service {
	return &Service{db: db}
}

// List lists the Customer's Areas across all its CMDB Sources, Disconnected
// ones included, sorted by name, then id. A Customer has tens of Areas, so
// the list is not paged. Active keeps only Active Areas when true and only
// Inactive ones when false; nil keeps both.
func (s *Service) List(ctx context.Context, caller tenancy.User, active *bool) ([]StoredArea, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return nil, err
	}
	return postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]StoredArea, error) {
		return tx.ListAreas(ctx, customer, active)
	})
}
