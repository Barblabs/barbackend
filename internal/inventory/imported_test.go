package inventory_test

import (
	"errors"
	"reflect"
	"testing"

	"barbackend/internal/inventory"
)

func TestNewImportedAsset(t *testing.T) {
	osc := inventory.SoftwareComponent{Role: inventory.OperatingSystem, Name: "Ubuntu", Version: "22.04"}
	app := inventory.SoftwareComponent{Role: inventory.Application, Name: "nginx"}
	hw := &inventory.Hardware{Vendor: "Dell", Model: "R740"}

	tests := []struct {
		name   string
		mutate func(*inventory.ImportedAssetParams)
		want   error
	}{
		{"valid minimal", func(*inventory.ImportedAssetParams) {}, nil},
		{"empty name", func(p *inventory.ImportedAssetParams) { p.Name = "" }, inventory.ErrEmptyName},
		{"whitespace name", func(p *inventory.ImportedAssetParams) { p.Name = " \t\n" }, inventory.ErrEmptyName},
		{"unset kind", func(p *inventory.ImportedAssetParams) { p.Kind = 0 }, inventory.ErrInvalidKind},
		{"out of range kind", func(p *inventory.ImportedAssetParams) { p.Kind = 99 }, inventory.ErrInvalidKind},
		{"hardware on server", func(p *inventory.ImportedAssetParams) { p.Hardware = hw }, nil},
		{"hardware on workstation", func(p *inventory.ImportedAssetParams) { p.Kind = inventory.Workstation; p.Hardware = hw }, nil},
		{"hardware on network device", func(p *inventory.ImportedAssetParams) { p.Kind = inventory.NetworkDevice; p.Hardware = hw }, nil},
		{"hardware on vm", func(p *inventory.ImportedAssetParams) { p.Kind = inventory.VirtualMachine; p.Hardware = hw }, inventory.ErrHardwareOnVirtual},
		{"empty hardware", func(p *inventory.ImportedAssetParams) { p.Hardware = &inventory.Hardware{} }, inventory.ErrInvalidHardware},
		{"whitespace hardware", func(p *inventory.ImportedAssetParams) {
			p.Hardware = &inventory.Hardware{Vendor: " \t", Model: "\n "}
		}, inventory.ErrInvalidHardware},
		{"hardware with only vendor", func(p *inventory.ImportedAssetParams) { p.Hardware = &inventory.Hardware{Vendor: "Dell"} }, nil},
		{"hardware with only model", func(p *inventory.ImportedAssetParams) { p.Hardware = &inventory.Hardware{Model: "R740"} }, nil},
		{"vm without hardware", func(p *inventory.ImportedAssetParams) { p.Kind = inventory.VirtualMachine }, nil},
		{"one os and app", func(p *inventory.ImportedAssetParams) { p.Software = []inventory.SoftwareComponent{osc, app} }, nil},
		{"two os", func(p *inventory.ImportedAssetParams) { p.Software = []inventory.SoftwareComponent{osc, osc} }, inventory.ErrMultipleOperatingSystems},
		{"two apps", func(p *inventory.ImportedAssetParams) { p.Software = []inventory.SoftwareComponent{app, app} }, nil},
		{"invalid role", func(p *inventory.ImportedAssetParams) {
			p.Software = []inventory.SoftwareComponent{{Name: "x"}}
		}, inventory.ErrInvalidSoftware},
		{"empty software name", func(p *inventory.ImportedAssetParams) {
			p.Software = []inventory.SoftwareComponent{{Role: inventory.Application}}
		}, inventory.ErrInvalidSoftware},
		{"whitespace software name", func(p *inventory.ImportedAssetParams) {
			p.Software = []inventory.SoftwareComponent{{Role: inventory.Application, Name: "  "}}
		}, inventory.ErrInvalidSoftware},
		{"product with empty vendor", func(p *inventory.ImportedAssetParams) {
			p.Software = []inventory.SoftwareComponent{{Role: inventory.Application, Name: "x", Product: &inventory.Product{Name: "n"}}}
		}, inventory.ErrInvalidSoftware},
		{"product with empty name", func(p *inventory.ImportedAssetParams) {
			p.Software = []inventory.SoftwareComponent{{Role: inventory.Application, Name: "x", Product: &inventory.Product{Vendor: "v"}}}
		}, inventory.ErrInvalidSoftware},
		{"product with whitespace vendor", func(p *inventory.ImportedAssetParams) {
			p.Software = []inventory.SoftwareComponent{{Role: inventory.Application, Name: "x", Product: &inventory.Product{Vendor: " ", Name: "n"}}}
		}, inventory.ErrInvalidSoftware},
		{"product with whitespace name", func(p *inventory.ImportedAssetParams) {
			p.Software = []inventory.SoftwareComponent{{Role: inventory.Application, Name: "x", Product: &inventory.Product{Vendor: "v", Name: "\t"}}}
		}, inventory.ErrInvalidSoftware},
		{"identified product", func(p *inventory.ImportedAssetParams) {
			p.Software = []inventory.SoftwareComponent{{Role: inventory.Application, Name: "x", Product: &inventory.Product{Vendor: "v", Name: "n"}}}
		}, nil},
		{"criticality high", func(p *inventory.ImportedAssetParams) { p.Criticality = inventory.CriticalityHigh }, nil},
		{"criticality out of range", func(p *inventory.ImportedAssetParams) { p.Criticality = 42 }, inventory.ErrInvalidCriticality},
		{"negative criticality", func(p *inventory.ImportedAssetParams) { p.Criticality = -1 }, inventory.ErrInvalidCriticality},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validParams()
			tt.mutate(&p)
			_, err := inventory.NewImportedAsset(p)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestImportedAssetZeroValues(t *testing.T) {
	a := mustImported(t, validParams())
	if a.Criticality() != inventory.CriticalityUnknown {
		t.Errorf("criticality = %v, want Unknown", a.Criticality())
	}
	if _, ok := a.Hardware(); ok {
		t.Error("unexpected hardware")
	}
	if _, ok := a.Owner(); ok {
		t.Error("unexpected owner")
	}
	if _, ok := a.OperatingSystem(); ok {
		t.Error("unexpected operating system")
	}
	if a.Retired() {
		t.Error("unexpected retired")
	}
	if got := a.Software(); got != nil {
		t.Errorf("Software() = %#v, want nil", got)
	}
}

func TestImportedAssetGetters(t *testing.T) {
	owner := mustOwner(t, "a@b.c")
	p := inventory.ImportedAssetParams{
		Name: "n", Description: "d", Kind: inventory.Server,
		Hardware:    &inventory.Hardware{Vendor: "Dell", Model: "R740"},
		Software:    []inventory.SoftwareComponent{{Role: inventory.OperatingSystem, Name: "Ubuntu", Version: "22.04"}},
		Criticality: inventory.CriticalityLow, Owner: owner, Retired: true,
	}
	a := mustImported(t, p)
	if got := a.Name(); got != "n" {
		t.Errorf("Name() = %q, want %q", got, "n")
	}
	if got := a.Description(); got != "d" {
		t.Errorf("Description() = %q, want %q", got, "d")
	}
	if got := a.Kind(); got != inventory.Server {
		t.Errorf("Kind() = %v, want %v", got, inventory.Server)
	}
	if hw, ok := a.Hardware(); !ok || hw != (inventory.Hardware{Vendor: "Dell", Model: "R740"}) {
		t.Errorf("Hardware() = %+v, %v; want Dell R740, true", hw, ok)
	}
	if got := a.Software(); !reflect.DeepEqual(got, p.Software) {
		t.Errorf("Software() = %+v, want %+v", got, p.Software)
	}
	if got := a.Criticality(); got != inventory.CriticalityLow {
		t.Errorf("Criticality() = %v, want %v", got, inventory.CriticalityLow)
	}
	if got, ok := a.Owner(); !ok || got != owner {
		t.Errorf("Owner() = %v, %v; want %v, true", got, ok, owner)
	}
	if got := a.Retired(); !got {
		t.Errorf("Retired() = %v, want true", got)
	}
}

func TestImportedAssetHardwareStoredRaw(t *testing.T) {
	p := validParams()
	p.Hardware = &inventory.Hardware{Vendor: " Dell ", Model: ""}
	a := mustImported(t, p)
	if hw, ok := a.Hardware(); !ok || hw != (inventory.Hardware{Vendor: " Dell ", Model: ""}) {
		t.Errorf("Hardware() = %+v, %v; want {Vendor:\" Dell \" Model:\"\"}, true", hw, ok)
	}
}

func TestImportedAssetOperatingSystem(t *testing.T) {
	app := inventory.SoftwareComponent{Role: inventory.Application, Name: "nginx"}
	osc := inventory.SoftwareComponent{Role: inventory.OperatingSystem, Name: "Ubuntu", Version: "22.04"}
	tests := []struct {
		name     string
		software []inventory.SoftwareComponent
		want     inventory.SoftwareComponent
		wantOK   bool
	}{
		{"none", nil, inventory.SoftwareComponent{}, false},
		{"only application", []inventory.SoftwareComponent{app}, inventory.SoftwareComponent{}, false},
		{"os first", []inventory.SoftwareComponent{osc, app}, osc, true},
		{"os after application", []inventory.SoftwareComponent{app, osc}, osc, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validParams()
			p.Software = tt.software
			got, ok := mustImported(t, p).OperatingSystem()
			if ok != tt.wantOK || !reflect.DeepEqual(got, tt.want) {
				t.Errorf("OperatingSystem() = %+v, %v; want %+v, %v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestImportedAssetIsolation(t *testing.T) {
	p := inventory.ImportedAssetParams{
		Name: "n", Kind: inventory.Server,
		Hardware: &inventory.Hardware{Vendor: "Dell", Model: "R740"},
		Software: []inventory.SoftwareComponent{
			{Role: inventory.OperatingSystem, Name: "Ubuntu", Product: &inventory.Product{Vendor: "Canonical", Name: "Ubuntu"}},
		},
	}
	a := mustImported(t, p)

	p.Hardware.Vendor = "X"
	p.Software[0].Name = "X"
	p.Software[0].Product.Name = "X"

	sw := a.Software()
	sw[0].Name = "Y"
	sw[0].Product.Vendor = "Y"
	osc, _ := a.OperatingSystem()
	osc.Product.Name = "Y"

	hw, _ := a.Hardware()
	got := a.Software()[0]
	if hw.Vendor != "Dell" || got.Name != "Ubuntu" || got.Product.Vendor != "Canonical" || got.Product.Name != "Ubuntu" {
		t.Errorf("internal state was mutated: hw=%+v sw=%+v", hw, got)
	}
}

func TestSoftwareComponentIdentified(t *testing.T) {
	tests := []struct {
		name string
		c    inventory.SoftwareComponent
		want bool
	}{
		{"identified", inventory.SoftwareComponent{Name: "x", Product: &inventory.Product{Vendor: "v", Name: "n"}}, true},
		{"unidentified", inventory.SoftwareComponent{Name: "x"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.Identified(); got != tt.want {
				t.Errorf("Identified() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAssetKindPhysical(t *testing.T) {
	tests := []struct {
		kind inventory.AssetKind
		want bool
	}{
		{inventory.Server, true},
		{inventory.VirtualMachine, false},
		{inventory.Workstation, true},
		{inventory.NetworkDevice, true},
		{0, false},
		{99, false},
	}
	for _, tt := range tests {
		t.Run(tt.kind.String(), func(t *testing.T) {
			if got := tt.kind.Physical(); got != tt.want {
				t.Errorf("Physical() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStringers(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"AssetKind/Server", inventory.Server.String(), "Server"},
		{"AssetKind/Virtual Machine", inventory.VirtualMachine.String(), "Virtual Machine"},
		{"AssetKind/Workstation", inventory.Workstation.String(), "Workstation"},
		{"AssetKind/Network Device", inventory.NetworkDevice.String(), "Network Device"},
		{"AssetKind/99", inventory.AssetKind(99).String(), "AssetKind(99)"},
		{"SoftwareRole/Operating System", inventory.OperatingSystem.String(), "Operating System"},
		{"SoftwareRole/Application", inventory.Application.String(), "Application"},
		{"SoftwareRole/99", inventory.SoftwareRole(99).String(), "SoftwareRole(99)"},
		{"Criticality/Unknown", inventory.CriticalityUnknown.String(), "Unknown"},
		{"Criticality/High", inventory.CriticalityHigh.String(), "High"},
		{"Criticality/Medium", inventory.CriticalityMedium.String(), "Medium"},
		{"Criticality/Low", inventory.CriticalityLow.String(), "Low"},
		{"Criticality/99", inventory.Criticality(99).String(), "Criticality(99)"},
		{"Exposure/Unknown", inventory.ExposureUnknown.String(), "Unknown"},
		{"Exposure/Internet-facing", inventory.InternetFacing.String(), "Internet-facing"},
		{"Exposure/Internal", inventory.Internal.String(), "Internal"},
		{"Exposure/99", inventory.Exposure(99).String(), "Exposure(99)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("String() = %q, want %q", tt.got, tt.want)
			}
		})
	}
}
