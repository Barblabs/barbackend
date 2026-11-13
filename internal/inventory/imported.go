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
	Exposure    Exposure
	Lifecycle   LifecycleStage
	Owner       OwnerEmail
	// Area is the RecordID of an AreaRecord in the same Snapshot, or "" for none.
	Area    string
	Retired bool
}

type ImportedAsset struct {
	name        string
	description string
	kind        AssetKind
	hardware    Hardware
	software    []SoftwareComponent
	criticality Criticality
	exposure    Exposure
	lifecycle   LifecycleStage
	owner       OwnerEmail
	area        string
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
	if !p.Exposure.valid() {
		return ImportedAsset{}, fmt.Errorf("%w: %d", ErrInvalidExposure, int(p.Exposure))
	}
	if !p.Lifecycle.valid() {
		return ImportedAsset{}, fmt.Errorf("%w: %d", ErrInvalidLifecycleStage, int(p.Lifecycle))
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
		exposure:    p.Exposure,
		lifecycle:   p.Lifecycle,
		owner:       p.Owner,
		area:        p.Area,
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

func (a ImportedAsset) isZero() bool { return a.name == "" }

func (a ImportedAsset) equal(b ImportedAsset) bool {
	return a.name == b.name &&
		a.description == b.description &&
		a.kind == b.kind &&
		a.hardware == b.hardware &&
		a.criticality == b.criticality &&
		a.exposure == b.exposure &&
		a.lifecycle == b.lifecycle &&
		a.owner == b.owner &&
		a.area == b.area &&
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

// Exposure is Unknown when the CMDB Source does not give it (ADR 0021).
func (a ImportedAsset) Exposure() Exposure { return a.exposure }

// Lifecycle is Unknown when the CMDB Source does not give it, and for a
// retired Asset (ADR 0028).
func (a ImportedAsset) Lifecycle() LifecycleStage { return a.lifecycle }

func (a ImportedAsset) Owner() (OwnerEmail, bool) {
	if a.owner.isZero() {
		return OwnerEmail{}, false
	}
	return a.owner, true
}

// Area returns the RecordID of the Asset's Area.
func (a ImportedAsset) Area() (string, bool) { return a.area, a.area != "" }

// Retired does not affect Asset.Active; the sync decides when a retired Asset
// becomes inactive (ADR 0005).
func (a ImportedAsset) Retired() bool { return a.retired }
