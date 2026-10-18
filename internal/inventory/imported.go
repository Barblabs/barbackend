package inventory

import (
	"fmt"
	"slices"
)

type ImportedAssetParams struct {
	Name        string
	Description string
	Kind        AssetKind
	Hardware    Hardware
	Software    []SoftwareComponent
	Criticality Criticality
	Owner       OwnerEmail
	Retired     bool
}

type ImportedAsset struct {
	name        string
	description string
	kind        AssetKind
	hardware    Hardware
	software    []SoftwareComponent
	criticality Criticality
	owner       OwnerEmail
	retired     bool
}

func NewImportedAsset(p ImportedAssetParams) (ImportedAsset, error) {
	if blank(p.Name) {
		return ImportedAsset{}, ErrEmptyName
	}
	if !p.Kind.valid() {
		return ImportedAsset{}, fmt.Errorf("%w: %d", ErrInvalidKind, int(p.Kind))
	}
	hardware := p.Hardware
	if hardware.absent() {
		hardware = Hardware{}
	}
	if hardware != (Hardware{}) && !p.Kind.Physical() {
		return ImportedAsset{}, fmt.Errorf("%w: %s", ErrHardwareOnVirtual, p.Kind)
	}
	if !p.Criticality.valid() {
		return ImportedAsset{}, fmt.Errorf("%w: %d", ErrInvalidCriticality, int(p.Criticality))
	}
	software, err := newSoftware(p.Software)
	if err != nil {
		return ImportedAsset{}, err
	}

	return ImportedAsset{
		name:        p.Name,
		description: p.Description,
		kind:        p.Kind,
		hardware:    hardware,
		software:    software,
		criticality: p.Criticality,
		owner:       p.Owner,
		retired:     p.Retired,
	}, nil
}

func newSoftware(components []SoftwareComponent) ([]SoftwareComponent, error) {
	software := slices.Clone(components)
	systems := 0
	for i, c := range software {
		if !c.Role.valid() {
			return nil, fmt.Errorf("%w: component %d has role %d", ErrInvalidSoftware, i, int(c.Role))
		}
		if blank(c.Name) {
			return nil, fmt.Errorf("%w: component %d has no name", ErrInvalidSoftware, i)
		}
		if c.Product.absent() {
			software[i].Product = Product{}
		} else if blank(c.Product.Vendor) || blank(c.Product.Name) {
			return nil, fmt.Errorf("%w: component %d has a product without vendor or name", ErrInvalidSoftware, i)
		}
		if c.Role == OperatingSystem {
			systems++
		}
	}
	if systems > 1 {
		return nil, ErrMultipleOperatingSystems
	}
	return software, nil
}

// A blank name is enough to detect the zero value: NewImportedAsset rejects it.
func (a ImportedAsset) isZero() bool { return a.name == "" }

// equal treats Software Components as a multiset: CMDB Sources do not promise
// a stable order, so a reordered list is not a change.
func (a ImportedAsset) equal(b ImportedAsset) bool {
	return a.name == b.name &&
		a.description == b.description &&
		a.kind == b.kind &&
		a.hardware == b.hardware &&
		a.criticality == b.criticality &&
		a.owner == b.owner &&
		a.retired == b.retired &&
		sameComponents(a.software, b.software)
}

func sameComponents(a, b []SoftwareComponent) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[SoftwareComponent]int, len(a))
	for _, c := range a {
		counts[c]++
	}
	for _, c := range b {
		if counts[c] == 0 {
			return false
		}
		counts[c]--
	}
	return true
}

func (a ImportedAsset) Name() string { return a.name }

func (a ImportedAsset) Description() string { return a.description }

func (a ImportedAsset) Kind() AssetKind { return a.kind }

func (a ImportedAsset) Hardware() (Hardware, bool) {
	return a.hardware, a.hardware != Hardware{}
}

func (a ImportedAsset) Software() []SoftwareComponent { return slices.Clone(a.software) }

func (a ImportedAsset) OperatingSystem() (SoftwareComponent, bool) {
	for _, c := range a.software {
		if c.Role == OperatingSystem {
			return c, true
		}
	}
	return SoftwareComponent{}, false
}

func (a ImportedAsset) Criticality() Criticality { return a.criticality }

func (a ImportedAsset) Owner() (OwnerEmail, bool) {
	if a.owner.isZero() {
		return OwnerEmail{}, false
	}
	return a.owner, true
}

// Retired does not affect Asset.Active; the sync decides when a retired Asset
// becomes inactive (ADR 0005).
func (a ImportedAsset) Retired() bool { return a.retired }
