package inventory

import "errors"

var ErrZeroImportedArea = errors.New("imported area is the zero value")

type ImportedAreaParams struct {
	Name string
	// Inactive is the CMDB Source's own status for the Area. It is not kept
	// apart from Active: Reconcile folds it into whether the Area is Active.
	Inactive bool
}

type ImportedArea struct {
	name     string
	inactive bool
}

func NewImportedArea(p ImportedAreaParams) (ImportedArea, error) {
	if blank(p.Name) {
		return ImportedArea{}, ErrEmptyName
	}
	return ImportedArea{name: p.Name, inactive: p.Inactive}, nil
}

func (a ImportedArea) isZero() bool { return a.name == "" }

func (a ImportedArea) Name() string { return a.name }

func (a ImportedArea) Inactive() bool { return a.inactive }

// Area is a part of the Customer's organization that Assets belong to, owned
// by the CMDB Source it was imported from. Its owner is stated by a Customer
// Admin, never imported, so a Sync keeps it.
type Area struct {
	ref      SourceReference
	imported ImportedArea
	active   bool
	owner    OwnerEmail
}

// AreaState is what barbattack itself holds about an Area. A zero owner means
// no owner.
type AreaState struct {
	Active bool
	Owner  OwnerEmail
}

func RestoreArea(ref SourceReference, imported ImportedArea, state AreaState) (*Area, error) {
	if err := ref.validate(); err != nil {
		return nil, err
	}
	if imported.isZero() {
		return nil, ErrZeroImportedArea
	}
	return &Area{ref: ref, imported: imported, active: state.Active, owner: state.Owner}, nil
}

func (a *Area) Ref() SourceReference { return a.ref }

func (a *Area) Imported() ImportedArea { return a.imported }

func (a *Area) Active() bool { return a.active }

func (a *Area) Owner() (OwnerEmail, bool) {
	if a.owner.isZero() {
		return OwnerEmail{}, false
	}
	return a.owner, true
}

// SetOwner with the zero OwnerEmail clears the owner.
func (a *Area) SetOwner(o OwnerEmail) { a.owner = o }
