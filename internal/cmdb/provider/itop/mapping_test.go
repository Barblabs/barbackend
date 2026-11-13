package itop

import (
	"reflect"
	"strings"
	"testing"

	"barbackend/internal/inventory"
)

func mapped(class string, change func(*ci)) ci {
	c := ci{
		Key: "7", Class: class, Name: "Server1", Description: "  Billing database\n", Status: "production",
		Criticality: ptr("low"), Brand: "HPE", Model: "DL380", OSFamily: "Red Hat", OSVersion: "9", OrgID: "3",
	}
	if change != nil {
		change(&c)
	}
	return c
}

// demo is the Organization every mapped ci belongs to.
var demo = []organization{{Key: "3", Name: "Demo", Status: "active"}}

func demoArea(t *testing.T) inventory.AreaRecord {
	t.Helper()
	imported, err := inventory.NewImportedArea(inventory.ImportedAreaParams{Name: "Demo"})
	if err != nil {
		t.Fatal(err)
	}
	return inventory.AreaRecord{RecordID: "3", Imported: imported}
}

func redHat() []inventory.SoftwareComponent {
	return []inventory.SoftwareComponent{{Role: inventory.OperatingSystem, Name: "Red Hat", Version: "9"}}
}

// expected is what mapped(class, nil) maps to for that kind, with change
// applied.
func expected(kind inventory.AssetKind, change func(*inventory.ImportedAssetParams)) inventory.ImportedAssetParams {
	p := inventory.ImportedAssetParams{
		Name: "Server1", Description: "  Billing database\n", Kind: kind, Lifecycle: inventory.LifecycleProduction,
		Hardware: inventory.Hardware{Vendor: "HPE", Model: "DL380"}, Software: redHat(), Criticality: inventory.CriticalityLow,
	}
	if change != nil {
		change(&p)
	}
	return p
}

type params = inventory.ImportedAssetParams

func noHardware(p *params) { p.Hardware = inventory.Hardware{} }

func TestSnapshotMapsRecords(t *testing.T) {
	cisco := lookups{iosVersions: map[string]iosVersion{"90": {Brand: "Cisco", Name: "15.2(7)E"}}}
	tests := []struct {
		name string
		ci   ci
		lk   lookups
		want inventory.ImportedAssetParams
	}{
		{name: "server", ci: mapped("Server", nil), want: expected(inventory.Server, nil)},
		{name: "virtual machine has no hardware", ci: mapped("VirtualMachine", nil), want: expected(inventory.VirtualMachine, noHardware)},
		{name: "pc is a workstation", ci: mapped("PC", nil), want: expected(inventory.Workstation, nil)},
		{
			name: "obsolete is retired, with no lifecycle stage",
			ci:   mapped("Server", func(c *ci) { c.Status = "obsolete" }),
			want: expected(inventory.Server, func(p *params) { p.Lifecycle, p.Retired = inventory.LifecycleUnknown, true }),
		},
		{
			name: "implementation is not retired",
			ci:   mapped("Server", func(c *ci) { c.Status = "implementation" }),
			want: expected(inventory.Server, func(p *params) { p.Lifecycle = inventory.LifecycleImplementation }),
		},
		{
			name: "stock is not retired",
			ci:   mapped("Server", func(c *ci) { c.Status = "stock" }),
			want: expected(inventory.Server, func(p *params) { p.Lifecycle = inventory.LifecycleStock }),
		},
		{
			name: "status is matched ignoring case and spaces",
			ci:   mapped("Server", func(c *ci) { c.Status = " Stock " }),
			want: expected(inventory.Server, func(p *params) { p.Lifecycle = inventory.LifecycleStock }),
		},
		{
			name: "other status is unknown lifecycle stage",
			ci:   mapped("Server", func(c *ci) { c.Status = "test" }),
			want: expected(inventory.Server, func(p *params) { p.Lifecycle = inventory.LifecycleUnknown }),
		},
		{
			name: "high criticality",
			ci:   mapped("Server", func(c *ci) { c.Criticality = ptr("high") }),
			want: expected(inventory.Server, func(p *params) { p.Criticality = inventory.CriticalityHigh }),
		},
		{
			name: "medium criticality",
			ci:   mapped("Server", func(c *ci) { c.Criticality = ptr("medium") }),
			want: expected(inventory.Server, func(p *params) { p.Criticality = inventory.CriticalityMedium }),
		},
		{
			name: "blank criticality is unknown",
			ci:   mapped("Server", func(c *ci) { c.Criticality = nil }),
			want: expected(inventory.Server, func(p *params) { p.Criticality = inventory.CriticalityUnknown }),
		},
		{
			name: "exposed location is internet facing",
			ci:   mapped("Server", func(c *ci) { c.Location = "exposed" }),
			want: expected(inventory.Server, func(p *params) { p.Exposure = inventory.InternetFacing }),
		},
		{
			name: "not exposed location is internal",
			ci:   mapped("Server", func(c *ci) { c.Location = "not exposed" }),
			want: expected(inventory.Server, func(p *params) { p.Exposure = inventory.Internal }),
		},
		{
			name: "location is matched ignoring case and spaces",
			ci:   mapped("Server", func(c *ci) { c.Location = " Not Exposed " }),
			want: expected(inventory.Server, func(p *params) { p.Exposure = inventory.Internal }),
		},
		{
			name: "blank location is unknown exposure",
			ci:   mapped("Server", func(c *ci) { c.Location = "" }),
			want: expected(inventory.Server, func(p *params) { p.Exposure = inventory.ExposureUnknown }),
		},
		{
			name: "other location is unknown exposure",
			ci:   mapped("Server", func(c *ci) { c.Location = "Guadalajara" }),
			want: expected(inventory.Server, func(p *params) { p.Exposure = inventory.ExposureUnknown }),
		},
		{
			name: "pc takes exposure from its location",
			ci:   mapped("PC", func(c *ci) { c.Location = "exposed" }),
			want: expected(inventory.Workstation, func(p *params) { p.Exposure = inventory.InternetFacing }),
		},
		{
			name: "hardware with only a vendor",
			ci:   mapped("Server", func(c *ci) { c.Model = "" }),
			want: expected(inventory.Server, func(p *params) { p.Hardware = inventory.Hardware{Vendor: "HPE"} }),
		},
		{
			name: "no hardware when vendor and model are blank",
			ci:   mapped("PC", func(c *ci) { c.Brand, c.Model = "", " " }),
			want: expected(inventory.Workstation, noHardware),
		},
		{
			name: "no operating system when its name is blank",
			ci:   mapped("Server", func(c *ci) { c.OSFamily = "" }),
			want: expected(inventory.Server, func(p *params) { p.Software = nil }),
		},
		{
			name: "applications named after their instances and identified by their Software, and one with a blank vendor kept unidentified",
			ci: mapped("Server", func(c *ci) {
				c.Instances = []instance{{Class: "DBServer", Name: "db", SoftwareID: "2"}, {Class: "OtherSoftware", Name: "portal", SoftwareID: "7"}}
			}),
			lk: lookups{software: map[string]software{
				"2": {Vendor: "Oracle", Name: "Oracle DB engine", Version: "19c"},
				"7": {Name: "Internal portal", Version: "3.1"},
			}},
			want: expected(inventory.Server, func(p *params) {
				p.Software = append(redHat(),
					inventory.SoftwareComponent{
						Role: inventory.Application, Name: "db", Version: "19c",
						Product: inventory.Product{Vendor: "Oracle", Name: "Oracle DB engine"},
					},
					inventory.SoftwareComponent{Role: inventory.Application, Name: "portal", Version: "3.1"},
				)
			}),
		},
		{
			name: "network device os is its IOSVersion",
			ci: mapped("NetworkDevice", func(c *ci) {
				c.Brand, c.Model, c.OSFamily, c.OSVersion, c.IOSVersionID = "Cisco", "Cisco 6500", "", "", "90"
			}),
			lk: cisco,
			want: expected(inventory.NetworkDevice, func(p *params) {
				p.Hardware = inventory.Hardware{Vendor: "Cisco", Model: "Cisco 6500"}
				p.Software = []inventory.SoftwareComponent{{Role: inventory.OperatingSystem, Name: "Cisco", Version: "15.2(7)E"}}
			}),
		},
		{
			name: "network device without IOSVersion has no os",
			ci: mapped("NetworkDevice", func(c *ci) {
				c.OSFamily, c.OSVersion, c.IOSVersionID = "", "", blankKey
			}),
			lk:   cisco,
			want: expected(inventory.NetworkDevice, func(p *params) { p.Software = nil }),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want.Area = "3"
			imported, err := inventory.NewImportedAsset(tt.want)
			if err != nil {
				t.Fatal(err)
			}
			want := inventory.Snapshot{
				Areas:   []inventory.AreaRecord{demoArea(t)},
				Records: []inventory.Record{{RecordID: "7", Imported: imported}},
			}
			if got := snapshot([]ci{tt.ci}, demo, tt.lk); !reflect.DeepEqual(got, want) {
				t.Errorf("snapshot:\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

func TestSnapshotSkipsRecords(t *testing.T) {
	tests := []struct {
		name   string
		ci     ci
		reason string
	}{
		{"unknown criticality", mapped("Server", func(c *ci) { c.Criticality = ptr("critical") }), `business_criticity "critical"`},
		{"rejected by the domain", mapped("Server", func(c *ci) { c.Name = " " }), inventory.ErrEmptyName.Error()},
		{"organization not read", mapped("Server", func(c *ci) { c.OrgID = "9" }), "organization 9 is not readable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := snapshot([]ci{tt.ci}, demo, lookups{})
			if len(got.Records) != 0 || len(got.Skipped) != 1 {
				t.Fatalf("snapshot = %+v, want one Skipped Record", got)
			}
			if s := got.Skipped[0]; s.RecordID != "7" || !strings.Contains(s.Reason, tt.reason) {
				t.Errorf("skipped = %+v, want record 7 with a reason containing %q", s, tt.reason)
			}
		})
	}
}

func TestSnapshotKeepsMappingAfterASkippedRecord(t *testing.T) {
	skipped := mapped("Server", func(c *ci) { c.Key, c.Name = "1", "" })
	kept := mapped("Server", func(c *ci) { c.Key = "2" })
	got := snapshot([]ci{skipped, kept}, demo, lookups{})
	if len(got.Skipped) != 1 || got.Skipped[0].RecordID != "1" || len(got.Records) != 1 || got.Records[0].RecordID != "2" {
		t.Errorf("snapshot = %+v, want record 1 skipped and record 2 kept", got)
	}
}

func TestSnapshotMapsOrganizationsToAreas(t *testing.T) {
	orgs := []organization{
		{Key: "1", Name: "My Company", Status: "active"},
		{Key: "2", Name: "Old Branch", Status: "inactive"},
	}
	got := snapshot(nil, orgs, lookups{})
	var want []inventory.AreaRecord
	for _, p := range []struct {
		id string
		inventory.ImportedAreaParams
	}{
		{"1", inventory.ImportedAreaParams{Name: "My Company"}},
		{"2", inventory.ImportedAreaParams{Name: "Old Branch", Inactive: true}},
	} {
		imported, err := inventory.NewImportedArea(p.ImportedAreaParams)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, inventory.AreaRecord{RecordID: p.id, Imported: imported})
	}
	if !reflect.DeepEqual(got.Areas, want) {
		t.Errorf("areas:\n got %+v\nwant %+v", got.Areas, want)
	}
}

func TestSnapshotSkipsTheCIsOfAnOrganizationTheDomainRejects(t *testing.T) {
	orgs := []organization{{Key: "3", Name: " ", Status: "active"}}
	got := snapshot([]ci{mapped("Server", nil)}, orgs, lookups{})
	if len(got.Areas) != 0 || len(got.Records) != 0 || len(got.Skipped) != 1 {
		t.Fatalf("snapshot = %+v, want no Areas and one Skipped Record", got)
	}
	if reason := got.Skipped[0].Reason; !strings.Contains(reason, "organization 3 is not readable") {
		t.Errorf("reason = %q", reason)
	}
}
