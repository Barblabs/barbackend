package inventory

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidSourceReference   = errors.New("invalid source reference")
	ErrInvalidKind              = errors.New("invalid asset kind")
	ErrEmptyName                = errors.New("asset name is required")
	ErrHardwareOnVirtual        = errors.New("virtual machine cannot have hardware")
	ErrInvalidSoftware          = errors.New("invalid software component")
	ErrMultipleOperatingSystems = errors.New("asset has more than one operating system")
	ErrInvalidCriticality       = errors.New("invalid criticality")
	ErrInvalidExposure          = errors.New("invalid exposure")
	ErrEmptyOwnerEmail          = errors.New("owner email is empty")
	ErrZeroImportedAsset        = errors.New("imported asset is the zero value")
)

type SourceReference struct {
	Source   CMDBSourceID
	RecordID string
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
	assetKindCodes    = map[AssetKind]string{Server: "server", VirtualMachine: "virtual_machine", Workstation: "workstation", NetworkDevice: "network_device"}
	criticalityCodes  = map[Criticality]string{CriticalityHigh: "high", CriticalityMedium: "medium", CriticalityLow: "low"}
	exposureCodes     = map[Exposure]string{InternetFacing: "internet_facing", Internal: "internal"}
	softwareRoleCodes = map[SoftwareRole]string{OperatingSystem: "operating_system", Application: "application"}
)

// Code is the stable lowercase snake_case name clients use for the kind, or
// empty for a value that is not one.
func (k AssetKind) Code() string { return assetKindCodes[k] }

// ParseAssetKind is the inverse of AssetKind.Code.
func ParseAssetKind(code string) (AssetKind, error) {
	for k, c := range assetKindCodes {
		if c == code {
			return k, nil
		}
	}
	return 0, fmt.Errorf("%w: %q", ErrInvalidKind, code)
}

// Code is the stable lowercase snake_case name clients use for the
// criticality, or empty for Unknown, which is never shown as a value.
func (c Criticality) Code() string { return criticalityCodes[c] }

// ParseCriticality is the inverse of Criticality.Code. Unknown has no code.
func ParseCriticality(code string) (Criticality, error) {
	for c, name := range criticalityCodes {
		if name == code {
			return c, nil
		}
	}
	return 0, fmt.Errorf("%w: %q", ErrInvalidCriticality, code)
}

// Code is the stable lowercase snake_case name clients use for the exposure,
// or empty for Unknown.
func (e Exposure) Code() string { return exposureCodes[e] }

// Code is the stable lowercase snake_case name clients use for the role.
func (r SoftwareRole) Code() string { return softwareRoleCodes[r] }
