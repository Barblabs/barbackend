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
	if d := declared.ExposureAudit; d == nil || d.By != "admin@example.com" || d.At.IsZero() {
		t.Errorf("ExposureAudit = %+v, want by admin@example.com at a time", d)
	}

	declareExposure(t, db, customer, id, inventory.ExposureUnknown, admin.ID())

	cleared := onlyAsset(t, db, customer)
	if got := cleared.Asset.Exposure(); got != inventory.ExposureUnknown {
		t.Errorf("after clearing Exposure() = %v, want Unknown", got)
	}
	if cleared.ExposureAudit != nil {
		t.Errorf("after clearing ExposureAudit = %+v, want nil", cleared.ExposureAudit)
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
