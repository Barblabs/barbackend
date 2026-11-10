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

func mustImportedArea(t *testing.T, name string, inactive bool) inventory.ImportedArea {
	t.Helper()
	a, err := inventory.NewImportedArea(inventory.ImportedAreaParams{Name: name, Inactive: inactive})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func restoreArea(t *testing.T, id, name string, state inventory.AreaState) *inventory.Area {
	t.Helper()
	a, err := inventory.RestoreArea(inventory.SourceReference{Source: sourceID, RecordID: id}, mustImportedArea(t, name, false), state)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
