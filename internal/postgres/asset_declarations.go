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
	locked, err := t.q.LockCustomerAsset(ctx, sqlcgen.LockCustomerAssetParams{ID: id, CustomerID: uuid.UUID(customer)})
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredAsset{}, fmt.Errorf("asset %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return StoredAsset{}, fmt.Errorf("lock asset %d: %w", id, err)
	}
	ref := sqlcgen.ListAssetsByReferenceParams{SourceIds: []uuid.UUID{locked.CmdbSourceID}, RecordIds: []string{locked.RecordID}}
	rows, err := t.q.ListAssetsByReference(ctx, ref)
	if err != nil {
		return StoredAsset{}, fmt.Errorf("read asset %d: %w", id, err)
	}
	if len(rows) != 1 {
		return StoredAsset{}, fmt.Errorf("read asset %d: got %d rows for its lock", id, len(rows))
	}
	components, err := t.q.ListSoftwareComponentsOf(ctx, sqlcgen.ListSoftwareComponentsOfParams(ref))
	if err != nil {
		return StoredAsset{}, fmt.Errorf("list software of asset %d: %w", id, err)
	}
	return restoreAsset(sqlcgen.ListAssetsRow(rows[0]), softwareByAsset(components))
}

// DeclareExposure stores the Asset's declared Exposure as by's Declaration,
// made now. The caller has read the Asset with CustomerAsset in the same
// transaction and declared it there; a missing Asset is not reported.
func (t *Tx) DeclareExposure(ctx context.Context, a *inventory.Asset, by tenancy.UserID) error {
	ref := a.Ref()
	err := t.q.DeclareAssetExposure(ctx, sqlcgen.DeclareAssetExposureParams{
		DeclaredExposureID: int16(a.DeclaredExposure()), DeclaredBy: uuid.UUID(by),
		CmdbSourceID: uuid.UUID(ref.Source), RecordID: ref.RecordID,
	})
	if err != nil {
		return fmt.Errorf("declare exposure of %v: %w", ref, err)
	}
	return nil
}

// ClearExposureDeclaration clears the Asset's declared Exposure with who
// declared it and when. The caller has read the Asset with CustomerAsset in
// the same transaction; a missing Asset is not reported.
func (t *Tx) ClearExposureDeclaration(ctx context.Context, asset inventory.SourceReference) error {
	err := t.q.ClearAssetExposure(ctx, sqlcgen.ClearAssetExposureParams{CmdbSourceID: uuid.UUID(asset.Source), RecordID: asset.RecordID})
	if err != nil {
		return fmt.Errorf("clear exposure declaration of %v: %w", asset, err)
	}
	return nil
}

// DeclareInformationClassification stores the Asset's declared Information
// Classification as by's Declaration, made now. The caller has read the Asset
// with CustomerAsset in the same transaction and declared it there; a missing
// Asset is not reported.
func (t *Tx) DeclareInformationClassification(ctx context.Context, a *inventory.Asset, by tenancy.UserID) error {
	ref := a.Ref()
	err := t.q.DeclareAssetInformationClassification(ctx, sqlcgen.DeclareAssetInformationClassificationParams{
		DeclaredInformationClassificationID: int16(a.InformationClassification()), DeclaredBy: uuid.UUID(by),
		CmdbSourceID: uuid.UUID(ref.Source), RecordID: ref.RecordID,
	})
	if err != nil {
		return fmt.Errorf("declare information classification of %v: %w", ref, err)
	}
	return nil
}

// ClearInformationClassificationDeclaration clears the Asset's declared
// Information Classification with who declared it and when. The caller has
// read the Asset with CustomerAsset in the same transaction; a missing Asset
// is not reported.
func (t *Tx) ClearInformationClassificationDeclaration(ctx context.Context, asset inventory.SourceReference) error {
	err := t.q.ClearAssetInformationClassification(ctx, sqlcgen.ClearAssetInformationClassificationParams{
		CmdbSourceID: uuid.UUID(asset.Source), RecordID: asset.RecordID,
	})
	if err != nil {
		return fmt.Errorf("clear information classification declaration of %v: %w", asset, err)
	}
	return nil
}
