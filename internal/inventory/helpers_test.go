package inventory_test

import (
	"testing"

	"barbackend/internal/inventory"
	"github.com/google/uuid"
)

var sourceID = inventory.CMDBSourceID(uuid.New())

func validParams() inventory.ImportedAssetParams {
	return inventory.ImportedAssetParams{Name: "srv-01", Kind: inventory.Server}
}

func mustImported(t *testing.T, p inventory.ImportedAssetParams) inventory.ImportedAsset {
	t.Helper()
	a, err := inventory.NewImportedAsset(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func newAsset(t *testing.T, p inventory.ImportedAssetParams) *inventory.Asset {
	t.Helper()
	a, err := inventory.NewAsset(inventory.SourceReference{Source: sourceID, RecordID: "1"}, mustImported(t, p))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func mustOwner(t *testing.T, email string) inventory.OwnerEmail {
	t.Helper()
	o, err := inventory.NewOwnerEmail(email)
	if err != nil {
		t.Fatal(err)
	}
	return o
}
