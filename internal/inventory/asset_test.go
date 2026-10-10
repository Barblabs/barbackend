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
		{"valid", inventory.SourceReference{Source: "s", RecordID: "1"}, imported, nil},
		{"empty source", inventory.SourceReference{RecordID: "1"}, imported, inventory.ErrInvalidSourceReference},
		{"whitespace source", inventory.SourceReference{Source: " ", RecordID: "1"}, imported, inventory.ErrInvalidSourceReference},
		{"empty record id", inventory.SourceReference{Source: "s"}, imported, inventory.ErrInvalidSourceReference},
		{"whitespace record id", inventory.SourceReference{Source: "s", RecordID: "\t"}, imported, inventory.ErrInvalidSourceReference},
		{"empty reference", inventory.SourceReference{}, imported, inventory.ErrInvalidSourceReference},
		{"zero imported asset", inventory.SourceReference{Source: "s", RecordID: "1"}, inventory.ImportedAsset{}, inventory.ErrZeroImportedAsset},
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
	imported := inventory.OwnerEmail("imported@example.com")
	declared := inventory.OwnerEmail("declared@example.com")
	none := inventory.OwnerEmail("")

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

func TestAssetActiveState(t *testing.T) {
	a := newAsset(t, validParams())
	if !a.Active() {
		t.Fatal("new asset should be active")
	}
	a.MarkInactive()
	if a.Active() {
		t.Error("asset should be inactive")
	}
	a.Reactivate()
	if !a.Active() {
		t.Error("asset should be active again")
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

func TestAssetReplaceImported(t *testing.T) {
	imported := inventory.OwnerEmail("imported@example.com")
	declared := inventory.OwnerEmail("declared@example.com")

	p := validParams()
	p.Owner = imported
	a := newAsset(t, p)
	if err := a.DeclareOwner(declared); err != nil {
		t.Fatal(err)
	}
	if err := a.DeclareExposure(inventory.InternetFacing); err != nil {
		t.Fatal(err)
	}
	a.MarkInactive()

	next := mustImported(t, inventory.ImportedAssetParams{Name: "renamed", Kind: inventory.Workstation})
	if err := a.ReplaceImported(next); err != nil {
		t.Fatal(err)
	}

	if a.Imported().Name() != "renamed" || a.Imported().Kind() != inventory.Workstation {
		t.Errorf("imported not replaced: %q", a.Imported().Name())
	}
	if o, _ := a.Owner(); o != declared {
		t.Errorf("Owner() = %q, want declared", o)
	}
	if a.Exposure() != inventory.InternetFacing {
		t.Errorf("Exposure() = %v, want InternetFacing", a.Exposure())
	}
	if a.Active() {
		t.Error("active state should be untouched")
	}

	a.ClearOwnerDeclaration()
	if o, ok := a.Owner(); ok {
		t.Errorf("Owner() = %q, want none after replace and clear", o)
	}
}

func TestAssetDeclareBlankOwner(t *testing.T) {
	imported := inventory.OwnerEmail("imported@example.com")
	declared := inventory.OwnerEmail("declared@example.com")

	p := validParams()
	p.Owner = imported
	a := newAsset(t, p)

	for _, blank := range []inventory.OwnerEmail{"", "   "} {
		if err := a.DeclareOwner(blank); !errors.Is(err, inventory.ErrEmptyOwnerEmail) {
			t.Fatalf("DeclareOwner(%q) err = %v, want ErrEmptyOwnerEmail", blank, err)
		}
	}
	if o, ok := a.Owner(); !ok || o != imported {
		t.Errorf("Owner() = %v, %v; want imported", o, ok)
	}

	if err := a.DeclareOwner(declared); err != nil {
		t.Fatal(err)
	}
	if err := a.DeclareOwner(""); err == nil {
		t.Fatal("expected error")
	}
	if o, ok := a.Owner(); !ok || o != declared {
		t.Errorf("Owner() = %v, %v; want declared", o, ok)
	}
}

func TestAssetReplaceImportedRejectsZero(t *testing.T) {
	owner := inventory.OwnerEmail("o@example.com")
	p := validParams()
	p.Owner = owner
	a := newAsset(t, p)

	err := a.ReplaceImported(inventory.ImportedAsset{})
	if !errors.Is(err, inventory.ErrZeroImportedAsset) {
		t.Fatalf("err = %v, want ErrZeroImportedAsset", err)
	}
	if a.Imported().Name() != "srv-01" {
		t.Errorf("Name() = %q, want unchanged", a.Imported().Name())
	}
	if o, ok := a.Owner(); !ok || o != owner {
		t.Errorf("Owner() = %v, %v; want unchanged", o, ok)
	}
}

func TestAssetReplaceImportedNewOwnerWithoutDeclaration(t *testing.T) {
	first := inventory.OwnerEmail("first@example.com")
	second := inventory.OwnerEmail("second@example.com")
	p := validParams()
	p.Owner = first
	a := newAsset(t, p)

	p.Owner = second
	if err := a.ReplaceImported(mustImported(t, p)); err != nil {
		t.Fatal(err)
	}
	if o, ok := a.Owner(); !ok || o != second {
		t.Errorf("Owner() = %v, %v; want %v, true", o, ok, second)
	}
}

func TestRestoreAsset(t *testing.T) {
	ref := inventory.SourceReference{Source: "s", RecordID: "1"}
	imported := mustImported(t, validParams())
	tests := []struct {
		name  string
		ref   inventory.SourceReference
		state inventory.AssetState
		want  error
	}{
		{"active without declarations", ref, inventory.AssetState{Active: true}, nil},
		{"inactive with declarations", ref, inventory.AssetState{DeclaredOwner: "o@example.com", DeclaredExposure: inventory.Internal}, nil},
		{"invalid reference", inventory.SourceReference{Source: "s"}, inventory.AssetState{Active: true}, inventory.ErrInvalidSourceReference},
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
	p := validParams()
	p.Owner = "imported@example.com"
	a := newAsset(t, p)
	if got, ok := a.DeclaredOwner(); ok {
		t.Fatalf("DeclaredOwner() = %q, want none", got)
	}
	if err := a.DeclareOwner("declared@example.com"); err != nil {
		t.Fatal(err)
	}
	if got, ok := a.DeclaredOwner(); !ok || got != "declared@example.com" {
		t.Errorf("DeclaredOwner() = %q, %v; want declared@example.com, true", got, ok)
	}
}
