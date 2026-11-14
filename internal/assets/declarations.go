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
	return s.changeScoredDeclaration(ctx, caller, id, func(tx *postgres.Tx, a *inventory.Asset) error {
		if err := a.DeclareExposure(exposure); err != nil {
			return err
		}
		return tx.DeclareExposure(ctx, a, caller.ID())
	})
}

// ClearExposure withdraws the Declaration of the Customer's Asset with id, so
// its Exposure falls back to the imported one, and rescores the Asset's open
// Findings. Only a Customer Admin clears it, even on an Inactive Asset. The
// rescore runs after the clearing commits: if it fails, so does the call, but
// the Declaration stays cleared. It fails with ErrAssetNotFound.
func (s *Service) ClearExposure(ctx context.Context, caller tenancy.User, id int64) (StoredAsset, error) {
	return s.changeScoredDeclaration(ctx, caller, id, func(tx *postgres.Tx, a *inventory.Asset) error {
		return tx.ClearExposureDeclaration(ctx, a.Ref())
	})
}

// DeclareInformationClassification states how sensitive the data of the
// Customer's Asset with id is, as the caller's Declaration. Only a Customer
// Admin declares, never Unclassified, and only on an Active Asset. It is not
// scored, so nothing is rescored (ADR 0031). It fails with ErrAssetNotFound,
// inventory.ErrInvalidInformationClassification or inventory.ErrAssetInactive.
func (s *Service) DeclareInformationClassification(ctx context.Context, caller tenancy.User, id int64, c inventory.InformationClassification) (StoredAsset, error) {
	return s.changeDeclaration(ctx, caller, id, func(tx *postgres.Tx, a *inventory.Asset) error {
		if err := a.DeclareInformationClassification(c); err != nil {
			return err
		}
		return tx.DeclareInformationClassification(ctx, a, caller.ID())
	})
}

// ClearInformationClassification withdraws the Declaration of the Customer's
// Asset with id, so it is Unclassified again. Only a Customer Admin clears it,
// even on an Inactive Asset. It fails with ErrAssetNotFound.
func (s *Service) ClearInformationClassification(ctx context.Context, caller tenancy.User, id int64) (StoredAsset, error) {
	return s.changeDeclaration(ctx, caller, id, func(tx *postgres.Tx, a *inventory.Asset) error {
		return tx.ClearInformationClassificationDeclaration(ctx, a.Ref())
	})
}

func (s *Service) changeScoredDeclaration(ctx context.Context, caller tenancy.User, id int64, apply func(*postgres.Tx, *inventory.Asset) error) (StoredAsset, error) {
	stored, err := s.changeDeclaration(ctx, caller, id, apply)
	if err != nil {
		return StoredAsset{}, err
	}
	if err := s.rescorer.RescoreAsset(ctx, stored.Asset.Ref()); err != nil {
		return StoredAsset{}, fmt.Errorf("rescore asset %d after its declaration: %w", id, err)
	}
	return stored, nil
}

func (s *Service) changeDeclaration(ctx context.Context, caller tenancy.User, id int64, apply func(*postgres.Tx, *inventory.Asset) error) (StoredAsset, error) {
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
	return stored, err
}
