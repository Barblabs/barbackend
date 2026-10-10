package inventory

import (
	"fmt"
	"strings"
)

type Asset struct {
	ref      SourceReference
	imported ImportedAsset
	active   bool

	declaredOwner    OwnerEmail
	declaredExposure Exposure
}

func NewAsset(ref SourceReference, imported ImportedAsset) (*Asset, error) {
	if strings.TrimSpace(string(ref.Source)) == "" {
		return nil, fmt.Errorf("%w: empty source", ErrInvalidSourceReference)
	}
	if strings.TrimSpace(ref.RecordID) == "" {
		return nil, fmt.Errorf("%w: empty record id", ErrInvalidSourceReference)
	}
	if imported.isZero() {
		return nil, ErrZeroImportedAsset
	}
	return &Asset{ref: ref, imported: imported, active: true}, nil
}

func (a *Asset) Ref() SourceReference { return a.ref }

func (a *Asset) Imported() ImportedAsset { return a.imported }

func (a *Asset) Owner() (OwnerEmail, bool) {
	if !a.declaredOwner.blank() {
		return a.declaredOwner, true
	}
	return a.imported.Owner()
}

func (a *Asset) Exposure() Exposure { return a.declaredExposure }

func (a *Asset) DeclareOwner(o OwnerEmail) error {
	if o.blank() {
		return ErrEmptyOwnerEmail
	}
	a.declaredOwner = o
	return nil
}

func (a *Asset) ClearOwnerDeclaration() { a.declaredOwner = "" }

func (a *Asset) DeclareExposure(e Exposure) error {
	if !e.valid() || e == ExposureUnknown {
		return fmt.Errorf("%w: %d", ErrInvalidExposure, int(e))
	}
	a.declaredExposure = e
	return nil
}

func (a *Asset) ClearExposureDeclaration() { a.declaredExposure = ExposureUnknown }

func (a *Asset) ReplaceImported(imported ImportedAsset) error {
	if imported.isZero() {
		return ErrZeroImportedAsset
	}
	a.imported = imported
	return nil
}

func (a *Asset) Active() bool { return a.active }

func (a *Asset) MarkInactive() { a.active = false }

func (a *Asset) Reactivate() { a.active = true }
