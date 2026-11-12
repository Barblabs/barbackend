package assets

import (
	"context"
	"errors"
	"fmt"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
)

// DeclareExposure states the Exposure of the Customer's Asset with id over
// the imported one, as the caller's Declaration, and rescores the Asset's
// open Findings. Only a Customer Admin declares, only Internet-facing or
// Internal, and only on an Active Asset (ADR 0021). It fails with
// ErrAssetNotFound, inventory.ErrInvalidExposure or inventory.ErrAssetInactive.
func (s *Service) DeclareExposure(ctx context.Context, caller tenancy.User, id int64, exposure inventory.Exposure) (StoredAsset, error) {
	return s.declare(ctx, caller, id, func(a *inventory.Asset) error { return a.DeclareExposure(exposure) })
}

// ClearExposure withdraws the Declaration of the Customer's Asset with id, so
// its Exposure falls back to the imported one, and rescores the Asset's open
// Findings. Only a Customer Admin clears it, even on an Inactive Asset. It
// fails with ErrAssetNotFound.
func (s *Service) ClearExposure(ctx context.Context, caller tenancy.User, id int64) (StoredAsset, error) {
	return s.declare(ctx, caller, id, func(a *inventory.Asset) error {
		a.ClearExposureDeclaration()
		return nil
	})
}

// declare applies change to the Asset and stores it in one transaction, then
// rescores in another. A failed rescore fails the call but leaves the
// Declaration stored: the next Sync rescores every Active Asset anyway.
func (s *Service) declare(ctx context.Context, caller tenancy.User, id int64, change func(*inventory.Asset) error) (StoredAsset, error) {
	customer, err := caller.DeclareAssetValues()
	if err != nil {
		return StoredAsset{}, err
	}
	stored, err := postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) (StoredAsset, error) {
		current, err := tx.CustomerAsset(ctx, customer, id)
		if err != nil {
			return StoredAsset{}, err
		}
		if err := change(current.Asset); err != nil {
			return StoredAsset{}, err
		}
		if err := tx.SaveExposureDeclaration(ctx, current.Asset, caller.ID()); err != nil {
			return StoredAsset{}, err
		}
		return tx.CustomerAsset(ctx, customer, id)
	})
	if errors.Is(err, postgres.ErrNotFound) {
		return StoredAsset{}, fmt.Errorf("%w: %w", ErrAssetNotFound, err)
	}
	if err != nil {
		return StoredAsset{}, err
	}
	if err := s.rescorer.RescoreAsset(ctx, stored.Asset.Ref()); err != nil {
		return StoredAsset{}, fmt.Errorf("rescore asset %d after its declaration: %w", id, err)
	}
	return stored, nil
}
