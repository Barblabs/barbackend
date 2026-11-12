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

// SaveExposureDeclaration stores the Asset's declared Exposure as by's
// Declaration, made now, or clears it with its author and time when the
// Asset has none.
func (t *Tx) SaveExposureDeclaration(ctx context.Context, a *inventory.Asset, by tenancy.UserID) error {
	ref := a.Ref()
	var n int64
	var err error
	if declared := a.DeclaredExposure(); declared == inventory.ExposureUnknown {
		n, err = t.q.ClearAssetExposure(ctx, sqlcgen.ClearAssetExposureParams{CmdbSourceID: uuid.UUID(ref.Source), RecordID: ref.RecordID})
	} else {
		n, err = t.q.DeclareAssetExposure(ctx, sqlcgen.DeclareAssetExposureParams{
			DeclaredExposureID: int16(declared), DeclaredBy: uuid.UUID(by),
			CmdbSourceID: uuid.UUID(ref.Source), RecordID: ref.RecordID,
		})
	}
	if err != nil {
		return fmt.Errorf("save exposure declaration of %v: %w", ref, err)
	}
	if n == 0 {
		return fmt.Errorf("save exposure declaration of %v: %w", ref, ErrNotFound)
	}
	return nil
}
