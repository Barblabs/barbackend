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
		Criticality: ptr("low"), Brand: "HPE", Model: "DL380", OSFamily: "Red Hat", OSVersion: "9",
	}
	if change != nil {
		change(&c)
	}
	return c
}

func redHat() []inventory.SoftwareComponent {
	return []inventory.SoftwareComponent{{Role: inventory.OperatingSystem, Name: "Red Hat", Version: "9"}}
}

func TestSnapshotMapsRecords(t *testing.T) {
	cisco := lookups{iosVersions: map[string]iosVersion{"90": {Brand: "Cisco", Name: "15.2(7)E"}}}
	hpe := inventory.Hardware{Vendor: "HPE", Model: "DL380"}
	tests := []struct {
		name string
		ci   ci
		lk   lookups
		want inventory.ImportedAssetParams
	}{
		{
			name: "server",
			ci:   mapped("Server", nil),
			want: inventory.ImportedAssetParams{
				Name: "Server1", Description: "  Billing database\n", Kind: inventory.Server,
				Hardware: hpe, Software: redHat(), Criticality: inventory.CriticalityLow,
			},
		},
		{
			name: "virtual machine has no hardware",
			ci:   mapped("VirtualMachine", func(c *ci) { c.Brand, c.Model = "", "" }),
			want: inventory.ImportedAssetParams{
				Name: "Server1", Description: "  Billing database\n", Kind: inventory.VirtualMachine,
				Software: redHat(), Criticality: inventory.CriticalityLow,
			},
		},
		{
			name: "pc is a workstation",
			ci:   mapped("PC", nil),
			want: inventory.ImportedAssetParams{
				Name: "Server1", Description: "  Billing database\n", Kind: inventory.Workstation,
				Hardware: hpe, Software: redHat(), Criticality: inventory.CriticalityLow,
			},
		},
		{
			name: "obsolete is retired",
			ci:   mapped("Server", func(c *ci) { c.Status = "obsolete" }),
			want: inventory.ImportedAssetParams{
				Name: "Server1", Description: "  Billing database\n", Kind: inventory.Server,
				Hardware: hpe, Software: redHat(), Criticality: inventory.CriticalityLow, Retired: true,
			},
		},
		{
			name: "implementation is not retired",
			ci:   mapped("Server", func(c *ci) { c.Status = "implementation" }),
			want: inventory.ImportedAssetParams{
				Name: "Server1", Description: "  Billing database\n", Kind: inventory.Server,
				Hardware: hpe, Software: redHat(), Criticality: inventory.CriticalityLow,
			},
		},
		{
			name: "high criticality",
			ci:   mapped("Server", func(c *ci) { c.Criticality = ptr("high") }),
			want: inventory.ImportedAssetParams{
				Name: "Server1", Description: "  Billing database\n", Kind: inventory.Server,
				Hardware: hpe, Software: redHat(), Criticality: inventory.CriticalityHigh,
			},
		},
		{
			name: "medium criticality",
			ci:   mapped("Server", func(c *ci) { c.Criticality = ptr("medium") }),
			want: inventory.ImportedAssetParams{
				Name: "Server1", Description: "  Billing database\n", Kind: inventory.Server,
				Hardware: hpe, Software: redHat(), Criticality: inventory.CriticalityMedium,
			},
		},
		{
			name: "blank criticality is unknown",
			ci:   mapped("Server", func(c *ci) { c.Criticality = nil }),
			want: inventory.ImportedAssetParams{
				Name: "Server1", Description: "  Billing database\n", Kind: inventory.Server,
				Hardware: hpe, Software: redHat(), Criticality: inventory.CriticalityUnknown,
			},
		},
		{
			name: "hardware with only a vendor",
			ci:   mapped("Server", func(c *ci) { c.Model = "" }),
			want: inventory.ImportedAssetParams{
				Name: "Server1", Description: "  Billing database\n", Kind: inventory.Server,
				Hardware: inventory.Hardware{Vendor: "HPE"}, Software: redHat(), Criticality: inventory.CriticalityLow,
			},
		},
		{
			name: "no hardware when vendor and model are blank",
			ci:   mapped("PC", func(c *ci) { c.Brand, c.Model = "", " " }),
			want: inventory.ImportedAssetParams{
				Name: "Server1", Description: "  Billing database\n", Kind: inventory.Workstation,
				Software: redHat(), Criticality: inventory.CriticalityLow,
			},
		},
		{
			name: "no operating system when its name is blank",
			ci:   mapped("Server", func(c *ci) { c.OSFamily = "" }),
			want: inventory.ImportedAssetParams{
				Name: "Server1", Description: "  Billing database\n", Kind: inventory.Server,
				Hardware: hpe, Criticality: inventory.CriticalityLow,
			},
		},
		{
			name: "network device os is its IOSVersion",
			ci: mapped("NetworkDevice", func(c *ci) {
				c.Brand, c.Model, c.OSFamily, c.OSVersion, c.IOSVersionID = "Cisco", "Cisco 6500", "", "", "90"
			}),
			lk: cisco,
			want: inventory.ImportedAssetParams{
				Name: "Server1", Description: "  Billing database\n", Kind: inventory.NetworkDevice,
				Hardware:    inventory.Hardware{Vendor: "Cisco", Model: "Cisco 6500"},
				Software:    []inventory.SoftwareComponent{{Role: inventory.OperatingSystem, Name: "Cisco", Version: "15.2(7)E"}},
				Criticality: inventory.CriticalityLow,
			},
		},
		{
			name: "network device without IOSVersion has no os",
			ci: mapped("NetworkDevice", func(c *ci) {
				c.OSFamily, c.OSVersion, c.IOSVersionID = "", "", blankKey
			}),
			lk: cisco,
			want: inventory.ImportedAssetParams{
				Name: "Server1", Description: "  Billing database\n", Kind: inventory.NetworkDevice,
				Hardware: hpe, Criticality: inventory.CriticalityLow,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imported, err := inventory.NewImportedAsset(tt.want)
			if err != nil {
				t.Fatal(err)
			}
			want := inventory.Snapshot{Records: []inventory.Record{{RecordID: "7", Imported: imported}}}
			if got := snapshot([]ci{tt.ci}, tt.lk); !reflect.DeepEqual(got, want) {
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := snapshot([]ci{tt.ci}, lookups{})
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
	got := snapshot([]ci{skipped, kept}, lookups{})
	if len(got.Skipped) != 1 || got.Skipped[0].RecordID != "1" || len(got.Records) != 1 || got.Records[0].RecordID != "2" {
		t.Errorf("snapshot = %+v, want record 1 skipped and record 2 kept", got)
	}
}
