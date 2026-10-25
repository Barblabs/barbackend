package inventory_test

import (
	"errors"
	"testing"

	"barbackend/internal/inventory"
)

func TestNewAsset(t *testing.T) {
	imported := mustImported(t, validParams())
	tests := []struct {
		name     string
		ref      inventory.SourceReference
		imported inventory.ImportedAsset
		want     error
	}{
		{"valid", inventory.SourceReference{Source: sourceID, RecordID: "1"}, imported, nil},
		{"zero source", inventory.SourceReference{RecordID: "1"}, imported, inventory.ErrInvalidSourceReference},
		{"empty record id", inventory.SourceReference{Source: sourceID}, imported, inventory.ErrInvalidSourceReference},
		{"whitespace record id", inventory.SourceReference{Source: sourceID, RecordID: "\t"}, imported, inventory.ErrInvalidSourceReference},
		{"empty reference", inventory.SourceReference{}, imported, inventory.ErrInvalidSourceReference},
		{"zero imported asset", inventory.SourceReference{Source: sourceID, RecordID: "1"}, inventory.ImportedAsset{}, inventory.ErrZeroImportedAsset},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := inventory.NewAsset(tt.ref, tt.imported)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if err != nil {
				if a != nil {
					t.Errorf("asset = %+v, want nil on error", a)
				}
			} else {
				if !a.Active() {
					t.Error("new asset should be active")
				}
				if a.Ref() != tt.ref {
					t.Errorf("Ref() = %+v, want %+v", a.Ref(), tt.ref)
				}
				if a.Exposure() != inventory.ExposureUnknown {
					t.Errorf("Exposure() = %v, want Unknown", a.Exposure())
				}
			}
		})
	}
}

func TestAssetOwner(t *testing.T) {
	imported := mustOwner(t, "imported@example.com")
	declared := mustOwner(t, "declared@example.com")
	none := inventory.OwnerEmail{}

	tests := []struct {
		name     string
		imported inventory.OwnerEmail
		declare  bool
		clear    bool
		want     inventory.OwnerEmail
		wantOK   bool
	}{
		{"none", none, false, false, none, false},
		{"imported only", imported, false, false, imported, true},
		{"declared only", none, true, false, declared, true},
		{"declared wins", imported, true, false, declared, true},
		{"clearing falls back to imported", imported, true, true, imported, true},
		{"clearing with nothing imported", none, true, true, none, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validParams()
			p.Owner = tt.imported
			a := newAsset(t, p)
			if tt.declare {
				if err := a.DeclareOwner(declared); err != nil {
					t.Fatal(err)
				}
			}
			if tt.clear {
				a.ClearOwnerDeclaration()
			}
			got, ok := a.Owner()
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("Owner() = %q, %v; want %q, %v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestAssetExposure(t *testing.T) {
	tests := []struct {
		name    string
		declare inventory.Exposure
		want    inventory.Exposure
		wantErr bool
	}{
		{"internet facing", inventory.InternetFacing, inventory.InternetFacing, false},
		{"internal", inventory.Internal, inventory.Internal, false},
		{"unknown rejected", inventory.ExposureUnknown, inventory.ExposureUnknown, true},
		{"out of range rejected", 42, inventory.ExposureUnknown, true},
		{"negative rejected", -1, inventory.ExposureUnknown, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAsset(t, validParams())
			err := a.DeclareExposure(tt.declare)
			if tt.wantErr != errors.Is(err, inventory.ErrInvalidExposure) {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if a.Exposure() != tt.want {
				t.Errorf("Exposure() = %v, want %v", a.Exposure(), tt.want)
			}
			if err == nil {
				a.ClearExposureDeclaration()
				if a.Exposure() != inventory.ExposureUnknown {
					t.Errorf("after clear Exposure() = %v, want Unknown", a.Exposure())
				}
			}
		})
	}
}

func TestAssetRejectedExposureKeepsPrevious(t *testing.T) {
	a := newAsset(t, validParams())
	if err := a.DeclareExposure(inventory.Internal); err != nil {
		t.Fatal(err)
	}
	if err := a.DeclareExposure(inventory.ExposureUnknown); err == nil {
		t.Fatal("expected error")
	}
	if a.Exposure() != inventory.Internal {
		t.Errorf("Exposure() = %v, want Internal", a.Exposure())
	}
}

func TestAssetRetiredDoesNotAffectActive(t *testing.T) {
	p := validParams()
	p.Retired = true
	a := newAsset(t, p)
	if !a.Active() || !a.Imported().Retired() {
		t.Errorf("active = %v, retired = %v; want true, true", a.Active(), a.Imported().Retired())
	}
}

func TestAssetDeclareBlankOwner(t *testing.T) {
	imported := mustOwner(t, "imported@example.com")
	declared := mustOwner(t, "declared@example.com")

	p := validParams()
	p.Owner = imported
	a := newAsset(t, p)

	if err := a.DeclareOwner(inventory.OwnerEmail{}); !errors.Is(err, inventory.ErrEmptyOwnerEmail) {
		t.Fatalf("DeclareOwner(zero) err = %v, want ErrEmptyOwnerEmail", err)
	}
	if o, ok := a.Owner(); !ok || o != imported {
		t.Errorf("Owner() = %v, %v; want imported", o, ok)
	}

	if err := a.DeclareOwner(declared); err != nil {
		t.Fatal(err)
	}
	if err := a.DeclareOwner(inventory.OwnerEmail{}); err == nil {
		t.Fatal("expected error")
	}
	if o, ok := a.Owner(); !ok || o != declared {
		t.Errorf("Owner() = %v, %v; want declared", o, ok)
	}
}

func TestRestoreAsset(t *testing.T) {
	ref := inventory.SourceReference{Source: sourceID, RecordID: "1"}
	imported := mustImported(t, validParams())
	tests := []struct {
		name  string
		ref   inventory.SourceReference
		state inventory.AssetState
		want  error
	}{
		{"active without declarations", ref, inventory.AssetState{Active: true}, nil},
		{"inactive with declarations", ref, inventory.AssetState{DeclaredOwner: mustOwner(t, "o@example.com"), DeclaredExposure: inventory.Internal}, nil},
		{"invalid reference", inventory.SourceReference{Source: sourceID}, inventory.AssetState{Active: true}, inventory.ErrInvalidSourceReference},
		{"out of range exposure", ref, inventory.AssetState{DeclaredExposure: 42}, inventory.ErrInvalidExposure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := inventory.RestoreAsset(tt.ref, imported, tt.state)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if err != nil {
				return
			}
			owner, _ := a.DeclaredOwner()
			got := inventory.AssetState{Active: a.Active(), DeclaredOwner: owner, DeclaredExposure: a.Exposure()}
			if got != tt.state {
				t.Errorf("restored state = %+v, want %+v", got, tt.state)
			}
		})
	}
}

func TestAssetDeclaredOwnerIgnoresImported(t *testing.T) {
	declared := mustOwner(t, "declared@example.com")
	p := validParams()
	p.Owner = mustOwner(t, "imported@example.com")
	a := newAsset(t, p)
	if got, ok := a.DeclaredOwner(); ok {
		t.Fatalf("DeclaredOwner() = %v, want none", got)
	}
	if err := a.DeclareOwner(declared); err != nil {
		t.Fatal(err)
	}
	if got, ok := a.DeclaredOwner(); !ok || got != declared {
		t.Errorf("DeclaredOwner() = %v, %v; want %v, true", got, ok, declared)
	}
}
