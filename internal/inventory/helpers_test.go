package inventory_test

import (
	"testing"

	"barbackend/internal/inventory"
)

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
	a, err := inventory.NewAsset(inventory.SourceReference{Source: "src", RecordID: "1"}, mustImported(t, p))
	if err != nil {
		t.Fatal(err)
	}
	return a
}
