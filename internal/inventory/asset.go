package inventory

import (
	"fmt"
)

type Asset struct {
	ref      SourceReference
	imported ImportedAsset
	active   bool

	declaredOwner    OwnerEmail
	declaredExposure Exposure
}

func NewAsset(ref SourceReference, imported ImportedAsset) (*Asset, error) {
	if err := ref.validate(); err != nil {
		return nil, err
	}
	if imported.isZero() {
		return nil, ErrZeroImportedAsset
	}
	return &Asset{ref: ref, imported: imported, active: true}, nil
}

// AssetState is what barbattack itself holds about an Asset, as opposed to
// its imported values. A zero owner or an Unknown exposure means no Declaration.
type AssetState struct {
	Active           bool
	DeclaredOwner    OwnerEmail
	DeclaredExposure Exposure
}

func RestoreAsset(ref SourceReference, imported ImportedAsset, state AssetState) (*Asset, error) {
	a, err := NewAsset(ref, imported)
	if err != nil {
		return nil, err
	}
	if !state.DeclaredExposure.valid() {
		return nil, fmt.Errorf("%w: %d", ErrInvalidExposure, int(state.DeclaredExposure))
	}
	a.active = state.Active
	a.declaredOwner = state.DeclaredOwner
	a.declaredExposure = state.DeclaredExposure
	return a, nil
}

func (a *Asset) Ref() SourceReference { return a.ref }

func (a *Asset) Imported() ImportedAsset { return a.imported }

func (a *Asset) Owner() (OwnerEmail, bool) {
	if !a.declaredOwner.isZero() {
		return a.declaredOwner, true
	}
	return a.imported.Owner()
}

func (a *Asset) DeclaredOwner() (OwnerEmail, bool) {
	if a.declaredOwner.isZero() {
		return OwnerEmail{}, false
	}
	return a.declaredOwner, true
}

// Exposure is the declared Exposure, or the imported one when none is
// declared (ADR 0021).
func (a *Asset) Exposure() Exposure {
	if a.declaredExposure != ExposureUnknown {
		return a.declaredExposure
	}
	return a.imported.Exposure()
}

func (a *Asset) DeclaredExposure() Exposure { return a.declaredExposure }

func (a *Asset) DeclareOwner(o OwnerEmail) error {
	if o.isZero() {
		return ErrEmptyOwnerEmail
	}
	a.declaredOwner = o
	return nil
}

func (a *Asset) ClearOwnerDeclaration() { a.declaredOwner = OwnerEmail{} }

// DeclareExposure states the Asset's Exposure over the imported one. Unknown
// is no statement, and an Inactive Asset is not monitored, so neither can be
// declared; a Declaration made while Active survives deactivation (ADR 0021).
func (a *Asset) DeclareExposure(e Exposure) error {
	if !e.valid() || e == ExposureUnknown {
		return fmt.Errorf("%w: %d", ErrInvalidExposure, int(e))
	}
	if !a.active {
		return fmt.Errorf("%w: %v", ErrAssetInactive, a.ref)
	}
	a.declaredExposure = e
	return nil
}

func (a *Asset) ClearExposureDeclaration() { a.declaredExposure = ExposureUnknown }

func (a *Asset) Active() bool { return a.active }

func (a *Asset) MarkInactive() { a.active = false }

func (a *Asset) Reactivate() { a.active = true }
