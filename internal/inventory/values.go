package inventory

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidSourceReference           = errors.New("invalid source reference")
	ErrInvalidKind                      = errors.New("invalid asset kind")
	ErrEmptyName                        = errors.New("name is required")
	ErrHardwareOnVirtual                = errors.New("virtual machine cannot have hardware")
	ErrInvalidSoftware                  = errors.New("invalid software component")
	ErrMultipleOperatingSystems         = errors.New("asset has more than one operating system")
	ErrInvalidCriticality               = errors.New("invalid criticality")
	ErrInvalidExposure                  = errors.New("invalid exposure")
	ErrInvalidLifecycleStage            = errors.New("invalid lifecycle stage")
	ErrInvalidInformationClassification = errors.New("invalid information classification")
	ErrEmptyOwnerEmail                  = errors.New("owner email is empty")
	ErrZeroImportedAsset                = errors.New("imported asset is the zero value")
	// ErrAssetInactive is a Declaration asked of an Asset barbattack no longer
	// monitors.
	ErrAssetInactive = errors.New("asset is inactive")
)

type SourceReference struct {
	Source   CMDBSourceID
	RecordID string
}

func (r SourceReference) validate() error {
	if r.Source == (CMDBSourceID{}) {
		return fmt.Errorf("%w: zero source", ErrInvalidSourceReference)
	}
	if blank(r.RecordID) {
		return fmt.Errorf("%w: empty record id", ErrInvalidSourceReference)
	}
	return nil
}

type AssetKind int

// Stored as catalog ids (ADR 0006): never renumber.
const (
	Server         AssetKind = 1
	VirtualMachine AssetKind = 2
	Workstation    AssetKind = 3
	NetworkDevice  AssetKind = 4
)

func (k AssetKind) valid() bool { return k >= Server && k <= NetworkDevice }

func (k AssetKind) Physical() bool { return k.valid() && k != VirtualMachine }

func (k AssetKind) String() string {
	switch k {
	case Server:
		return "Server"
	case VirtualMachine:
		return "Virtual Machine"
	case Workstation:
		return "Workstation"
	case NetworkDevice:
		return "Network Device"
	default:
		return fmt.Sprintf("AssetKind(%d)", int(k))
	}
}

// Hardware with both fields blank is no hardware, as is the zero value.
type Hardware struct {
	Vendor, Model string
}

func (h Hardware) absent() bool { return blank(h.Vendor) && blank(h.Model) }

type SoftwareRole int

// Stored as catalog ids (ADR 0006): never renumber.
const (
	OperatingSystem SoftwareRole = 1
	Application     SoftwareRole = 2
)

func (r SoftwareRole) valid() bool { return r == OperatingSystem || r == Application }

func (r SoftwareRole) String() string {
	switch r {
	case OperatingSystem:
		return "Operating System"
	case Application:
		return "Application"
	default:
		return fmt.Sprintf("SoftwareRole(%d)", int(r))
	}
}

// Product has no version on purpose: the version stays on the SoftwareComponent,
// so one Product covers every version threat intelligence may name.
// A Product with both fields blank is no Product, as is the zero value.
type Product struct {
	Vendor, Name string
}

func (p Product) absent() bool { return blank(p.Vendor) && blank(p.Name) }

type SoftwareComponent struct {
	Role    SoftwareRole
	Name    string
	Version string
	Product Product
}

func (c SoftwareComponent) Identified() bool { return !c.Product.absent() }

type Criticality int

// Stored as catalog ids (ADR 0006): never renumber.
const (
	CriticalityUnknown Criticality = 0
	CriticalityHigh    Criticality = 1
	CriticalityMedium  Criticality = 2
	CriticalityLow     Criticality = 3
)

func (c Criticality) valid() bool { return c >= CriticalityUnknown && c <= CriticalityLow }

func (c Criticality) String() string {
	switch c {
	case CriticalityUnknown:
		return "Unknown"
	case CriticalityHigh:
		return "High"
	case CriticalityMedium:
		return "Medium"
	case CriticalityLow:
		return "Low"
	default:
		return fmt.Sprintf("Criticality(%d)", int(c))
	}
}

type Exposure int

// Stored as catalog ids (ADR 0006): never renumber.
const (
	ExposureUnknown Exposure = 0
	InternetFacing  Exposure = 1
	Internal        Exposure = 2
)

func (e Exposure) valid() bool { return e >= ExposureUnknown && e <= Internal }

func (e Exposure) String() string {
	switch e {
	case ExposureUnknown:
		return "Unknown"
	case InternetFacing:
		return "Internet-facing"
	case Internal:
		return "Internal"
	default:
		return fmt.Sprintf("Exposure(%d)", int(e))
	}
}

// LifecycleStage is where an Asset is in its life (ADR 0028). A retired Asset
// has none: being retired is ImportedAsset.Retired.
type LifecycleStage int

// Stored as catalog ids (ADR 0006): never renumber.
const (
	LifecycleUnknown        LifecycleStage = 0
	LifecycleProduction     LifecycleStage = 1
	LifecycleImplementation LifecycleStage = 2
	LifecycleStock          LifecycleStage = 3
)

func (s LifecycleStage) valid() bool { return s >= LifecycleUnknown && s <= LifecycleStock }

func (s LifecycleStage) String() string {
	switch s {
	case LifecycleUnknown:
		return "Unknown"
	case LifecycleProduction:
		return "Production"
	case LifecycleImplementation:
		return "Implementation"
	case LifecycleStock:
		return "Stock"
	default:
		return fmt.Sprintf("LifecycleStage(%d)", int(s))
	}
}

// InformationClassification is how sensitive the data an Asset holds is. It
// is only declared, and Unclassified until then (ADR 0031).
type InformationClassification int

// Stored as catalog ids (ADR 0006): never renumber.
const (
	Unclassified           InformationClassification = 0
	ClassifiedPublic       InformationClassification = 1
	ClassifiedPrivate      InformationClassification = 2
	ClassifiedConfidential InformationClassification = 3
)

func (c InformationClassification) valid() bool {
	return c >= Unclassified && c <= ClassifiedConfidential
}

func (c InformationClassification) String() string {
	switch c {
	case Unclassified:
		return "Unclassified"
	case ClassifiedPublic:
		return "Public"
	case ClassifiedPrivate:
		return "Private"
	case ClassifiedConfidential:
		return "Confidential"
	default:
		return fmt.Sprintf("InformationClassification(%d)", int(c))
	}
}

// OwnerEmail identifies an Asset Owner. Emails differing only in case or
// surrounding space name the same person (ADR 0003), so every edge gets the
// same canonical form from here. The zero value means no owner.
type OwnerEmail struct {
	address string
}

// NewOwnerEmail does not check email syntax: that belongs to the edge that
// receives it.
func NewOwnerEmail(s string) (OwnerEmail, error) {
	if blank(s) {
		return OwnerEmail{}, ErrEmptyOwnerEmail
	}
	return OwnerEmail{address: strings.ToLower(strings.TrimSpace(s))}, nil
}

func (o OwnerEmail) String() string { return o.address }

func (o OwnerEmail) isZero() bool { return o == OwnerEmail{} }

func blank(s string) bool { return strings.TrimSpace(s) == "" }

var (
	assetKindCodes                 = map[AssetKind]string{Server: "server", VirtualMachine: "virtual_machine", Workstation: "workstation", NetworkDevice: "network_device"}
	criticalityCodes               = map[Criticality]string{CriticalityHigh: "high", CriticalityMedium: "medium", CriticalityLow: "low"}
	exposureCodes                  = map[Exposure]string{InternetFacing: "internet_facing", Internal: "internal"}
	lifecycleCodes                 = map[LifecycleStage]string{LifecycleProduction: "production", LifecycleImplementation: "implementation", LifecycleStock: "stock"}
	informationClassificationCodes = map[InformationClassification]string{ClassifiedPublic: "public", ClassifiedPrivate: "private", ClassifiedConfidential: "confidential"}
	softwareRoleCodes              = map[SoftwareRole]string{OperatingSystem: "operating_system", Application: "application"}
)

// Code is the stable lowercase snake_case name clients use for the kind, or
// empty for a value that is not one.
func (k AssetKind) Code() string { return assetKindCodes[k] }

// ParseAssetKind is the inverse of AssetKind.Code.
func ParseAssetKind(code string) (AssetKind, error) {
	if k, ok := parseCode(assetKindCodes, code); ok {
		return k, nil
	}
	return 0, fmt.Errorf("%w: %q", ErrInvalidKind, code)
}

// Code is the stable lowercase snake_case name clients use for the
// criticality, or empty for Unknown, which is never shown as a value.
func (c Criticality) Code() string { return criticalityCodes[c] }

// ParseCriticality is the inverse of Criticality.Code. Unknown has no code.
func ParseCriticality(code string) (Criticality, error) {
	if c, ok := parseCode(criticalityCodes, code); ok {
		return c, nil
	}
	return 0, fmt.Errorf("%w: %q", ErrInvalidCriticality, code)
}

// Code is the stable lowercase snake_case name clients use for the exposure,
// or empty for Unknown.
func (e Exposure) Code() string { return exposureCodes[e] }

// ParseExposure is the inverse of Exposure.Code. Unknown has no code.
func ParseExposure(code string) (Exposure, error) {
	if e, ok := parseCode(exposureCodes, code); ok {
		return e, nil
	}
	return 0, fmt.Errorf("%w: %q", ErrInvalidExposure, code)
}

// Code is the stable lowercase snake_case name clients use for the lifecycle
// stage, or empty for Unknown.
func (s LifecycleStage) Code() string { return lifecycleCodes[s] }

// ParseLifecycleStage is the inverse of LifecycleStage.Code. Unknown has no
// code.
func ParseLifecycleStage(code string) (LifecycleStage, error) {
	if s, ok := parseCode(lifecycleCodes, code); ok {
		return s, nil
	}
	return 0, fmt.Errorf("%w: %q", ErrInvalidLifecycleStage, code)
}

// Code is the stable lowercase snake_case name clients use for the
// classification, or empty for Unclassified.
func (c InformationClassification) Code() string { return informationClassificationCodes[c] }

// ParseInformationClassification is the inverse of
// InformationClassification.Code. Unclassified has no code.
func ParseInformationClassification(code string) (InformationClassification, error) {
	if c, ok := parseCode(informationClassificationCodes, code); ok {
		return c, nil
	}
	return 0, fmt.Errorf("%w: %q", ErrInvalidInformationClassification, code)
}

// Code is the stable lowercase snake_case name clients use for the role.
func (r SoftwareRole) Code() string { return softwareRoleCodes[r] }

// ParseSoftwareRole is the inverse of SoftwareRole.Code.
func ParseSoftwareRole(code string) (SoftwareRole, error) {
	if r, ok := parseCode(softwareRoleCodes, code); ok {
		return r, nil
	}
	return 0, fmt.Errorf("%w: role %q", ErrInvalidSoftware, code)
}

func parseCode[T comparable](codes map[T]string, code string) (T, bool) {
	for v, c := range codes {
		if c == code {
			return v, true
		}
	}
	var zero T
	return zero, false
}
