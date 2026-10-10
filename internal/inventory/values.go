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
	ErrInvalidHardware          = errors.New("invalid hardware")
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

type Hardware struct {
	Vendor, Model string
}

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
type Product struct {
	Vendor, Name string
}

type SoftwareComponent struct {
	Role    SoftwareRole
	Name    string
	Version string
	Product *Product
}

func (c SoftwareComponent) Identified() bool { return c.Product != nil }

func (c SoftwareComponent) clone() SoftwareComponent {
	if c.Product != nil {
		p := *c.Product
		c.Product = &p
	}
	return c
}

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

type OwnerEmail string

func blank(s string) bool { return strings.TrimSpace(s) == "" }
