package inventory_test

import (
	"errors"
	"testing"

	"barbackend/internal/inventory"
)

func TestRestoreArea(t *testing.T) {
	imported := mustImportedArea(t, "IT Department", false)
	tests := []struct {
		name     string
		ref      inventory.SourceReference
		imported inventory.ImportedArea
		want     error
	}{
		{"valid", inventory.SourceReference{Source: sourceID, RecordID: "1"}, imported, nil},
		{"zero source", inventory.SourceReference{RecordID: "1"}, imported, inventory.ErrInvalidSourceReference},
		{"whitespace record id", inventory.SourceReference{Source: sourceID, RecordID: " "}, imported, inventory.ErrInvalidSourceReference},
		{"zero imported area", inventory.SourceReference{Source: sourceID, RecordID: "1"}, inventory.ImportedArea{}, inventory.ErrZeroImportedArea},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := inventory.RestoreArea(tt.ref, tt.imported, inventory.AreaState{Active: true})
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if err != nil && a != nil {
				t.Errorf("area = %+v, want nil on error", a)
			}
		})
	}
}

func TestAreaOwner(t *testing.T) {
	owner := mustOwner(t, "owner@example.com")
	a := restoreArea(t, "1", "IT Department", inventory.AreaState{Active: true, Owner: owner})
	if got, ok := a.Owner(); !ok || got != owner {
		t.Fatalf("Owner() = %v, %v; want %v, true", got, ok, owner)
	}
	other := mustOwner(t, "other@example.com")
	a.SetOwner(other)
	if got, ok := a.Owner(); !ok || got != other {
		t.Errorf("Owner() after SetOwner = %v, %v; want %v, true", got, ok, other)
	}
	a.SetOwner(inventory.OwnerEmail{})
	if got, ok := a.Owner(); ok {
		t.Errorf("Owner() after clearing = %v, true; want none", got)
	}
}
