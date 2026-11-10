// Package areas holds the use cases on a Customer's Areas: listing them
// across all its CMDB Sources and stating their owners (ADR 0008).
package areas

import (
	"context"
	"errors"
	"fmt"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
)

// ErrAreaNotFound is an Area the Customer does not have.
var ErrAreaNotFound = errors.New("area not found")

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

// SetOwner states the email of whom to reach about the Customer's Area with
// id, or clears it when email is nil. Only a Customer Admin states it, and a
// Sync keeps it. The email's syntax is checked by the edge that receives it.
func (s *Service) SetOwner(ctx context.Context, caller tenancy.User, id int64, email *string) (StoredArea, error) {
	customer, err := caller.ManageAreas()
	if err != nil {
		return StoredArea{}, err
	}
	var owner inventory.OwnerEmail
	if email != nil {
		if owner, err = inventory.NewOwnerEmail(*email); err != nil {
			return StoredArea{}, err
		}
	}
	stored, err := postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) (StoredArea, error) {
		return tx.SetAreaOwner(ctx, customer, id, owner)
	})
	if errors.Is(err, postgres.ErrNotFound) {
		return StoredArea{}, fmt.Errorf("%w: %w", ErrAreaNotFound, err)
	}
	return stored, err
}
