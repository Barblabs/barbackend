package postgres

import (
	"context"
	"errors"
	"fmt"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres/sqlcgen"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CustomerAsset reads the Customer's Asset with id, with its Software
// Components, and locks it until the transaction ends, so a Declaration and a
// Sync of the Asset take turns. It fails with ErrNotFound for an Asset of
// another Customer as for a missing one.
func (t *Tx) CustomerAsset(ctx context.Context, customer tenancy.CustomerID, id int64) (StoredAsset, error) {
	row, err := t.q.LockCustomerAsset(ctx, sqlcgen.LockCustomerAssetParams{ID: id, CustomerID: uuid.UUID(customer)})
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredAsset{}, fmt.Errorf("asset %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return StoredAsset{}, fmt.Errorf("read asset %d: %w", id, err)
	}
	components, err := t.q.ListSoftwareComponentsOf(ctx, sqlcgen.ListSoftwareComponentsOfParams{
		SourceIds: []uuid.UUID{row.CmdbSourceID}, RecordIds: []string{row.RecordID},
	})
	if err != nil {
		return StoredAsset{}, fmt.Errorf("list software of asset %d: %w", id, err)
	}
	return restoreAsset(sqlcgen.ListAssetsRow(row), softwareByAsset(components))
}

// DeclareExposure stores e as by's Declaration of the Asset's Exposure,
// made now.
func (t *Tx) DeclareExposure(ctx context.Context, asset inventory.SourceReference, e inventory.Exposure, by tenancy.UserID) error {
	err := t.q.DeclareAssetExposure(ctx, sqlcgen.DeclareAssetExposureParams{
		DeclaredExposureID: int16(e), DeclaredBy: uuid.UUID(by),
		CmdbSourceID: uuid.UUID(asset.Source), RecordID: asset.RecordID,
	})
	if err != nil {
		return fmt.Errorf("declare exposure of %v: %w", asset, err)
	}
	return nil
}

// ClearExposureDeclaration clears the Asset's declared Exposure with who
// declared it and when.
func (t *Tx) ClearExposureDeclaration(ctx context.Context, asset inventory.SourceReference) error {
	err := t.q.ClearAssetExposure(ctx, sqlcgen.ClearAssetExposureParams{CmdbSourceID: uuid.UUID(asset.Source), RecordID: asset.RecordID})
	if err != nil {
		return fmt.Errorf("clear exposure declaration of %v: %w", asset, err)
	}
	return nil
}
