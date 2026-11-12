package postgres_test

import (
	"context"
	"errors"
	"testing"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/tenancy"
)

// onlyAsset is the one Asset of the Customer, as the Asset list reads it.
func onlyAsset(t *testing.T, db *postgres.DB, customer tenancy.CustomerID) postgres.StoredAsset {
	t.Helper()
	var page postgres.AssetPage
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		page, err = tx.ListAssets(context.Background(), postgres.AssetListQuery{Customer: customer, Limit: 10})
		return err
	})
	if len(page.Assets) != 1 {
		t.Fatalf("assets = %d, want 1", len(page.Assets))
	}
	return page.Assets[0]
}

func declareExposure(t *testing.T, db *postgres.DB, customer tenancy.CustomerID, id int64, e inventory.Exposure, by tenancy.UserID) {
	t.Helper()
	inTx(t, db, func(tx *postgres.Tx) error {
		stored, err := tx.CustomerAsset(context.Background(), customer, id)
		if err != nil {
			return err
		}
		if e == inventory.ExposureUnknown {
			return tx.ClearExposureDeclaration(context.Background(), stored.Asset.Ref())
		}
		return tx.DeclareExposure(context.Background(), stored.Asset.Ref(), e, by)
	})
}

func TestAnExposureDeclarationIsStoredWithItsAuthorAndClearedWithThem(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	customer := newCustomer(t, db)
	src := newSource(t, db, customer)
	admin := storeUser(t, db, "admin@example.com", tenancy.CustomerAdmin, customer)
	syncRecords(t, db, src.ID(), record(t, "vm", inventory.ImportedAssetParams{Name: "vm-01", Kind: inventory.VirtualMachine}))
	id := onlyAsset(t, db, customer).ID

	declareExposure(t, db, customer, id, inventory.Internal, admin.ID())

	declared := onlyAsset(t, db, customer)
	if got := declared.Asset.Exposure(); got != inventory.Internal {
		t.Errorf("Exposure() = %v, want Internal", got)
	}
	if d := declared.ExposureDeclaration; d == nil || d.By != "admin@example.com" || d.At.IsZero() {
		t.Errorf("ExposureDeclaration = %+v, want by admin@example.com at a time", d)
	}

	declareExposure(t, db, customer, id, inventory.ExposureUnknown, admin.ID())

	cleared := onlyAsset(t, db, customer)
	if got := cleared.Asset.Exposure(); got != inventory.ExposureUnknown {
		t.Errorf("after clearing Exposure() = %v, want Unknown", got)
	}
	if cleared.ExposureDeclaration != nil {
		t.Errorf("after clearing ExposureDeclaration = %+v, want nil", cleared.ExposureDeclaration)
	}
}

func TestAnAssetOfAnotherCustomerIsNotFoundByItsID(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	customer := newCustomer(t, db)
	syncRecords(t, db, newSource(t, db, customer).ID(), record(t, "vm", inventory.ImportedAssetParams{Name: "vm-01", Kind: inventory.VirtualMachine}))
	id := onlyAsset(t, db, customer).ID

	err := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.CustomerAsset(context.Background(), newCustomer(t, db), id)
		return err
	})
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
