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
// Internal, and only on an Active Asset (ADR 0021). The rescore runs after the
// Declaration commits: if it fails, so does the call, but the Declaration
// stands. It fails with ErrAssetNotFound, inventory.ErrInvalidExposure or
// inventory.ErrAssetInactive.
func (s *Service) DeclareExposure(ctx context.Context, caller tenancy.User, id int64, exposure inventory.Exposure) (StoredAsset, error) {
	return s.declare(ctx, caller, id, func(tx *postgres.Tx, a *inventory.Asset) error {
		if err := a.DeclareExposure(exposure); err != nil {
			return err
		}
		return tx.DeclareExposure(ctx, a.Ref(), exposure, caller.ID())
	})
}

// ClearExposure withdraws the Declaration of the Customer's Asset with id, so
// its Exposure falls back to the imported one, and rescores the Asset's open
// Findings. Only a Customer Admin clears it, even on an Inactive Asset. The
// rescore runs after the clearing commits: if it fails, so does the call, but
// the Declaration stays cleared. It fails with ErrAssetNotFound.
func (s *Service) ClearExposure(ctx context.Context, caller tenancy.User, id int64) (StoredAsset, error) {
	return s.declare(ctx, caller, id, func(tx *postgres.Tx, a *inventory.Asset) error {
		return tx.ClearExposureDeclaration(ctx, a.Ref())
	})
}

func (s *Service) declare(ctx context.Context, caller tenancy.User, id int64, apply func(*postgres.Tx, *inventory.Asset) error) (StoredAsset, error) {
	customer, err := caller.DeclareAssetValues()
	if err != nil {
		return StoredAsset{}, err
	}
	stored, err := postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) (StoredAsset, error) {
		current, err := tx.CustomerAsset(ctx, customer, id)
		if err != nil {
			return StoredAsset{}, err
		}
		if err := apply(tx, current.Asset); err != nil {
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
