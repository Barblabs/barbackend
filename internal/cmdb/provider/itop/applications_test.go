package itop

import (
	"reflect"
	"testing"

	"barbackend/internal/inventory"
)

func TestApplications(t *testing.T) {
	lk := lookups{software: map[string]software{
		"2": {Vendor: "Oracle", Name: "Oracle DB engine", Version: "19c"},
		"5": {Vendor: "OpenBSD", Name: "OpenSSH", Version: "9.6p1"},
		"7": {Vendor: " ", Name: "Internal portal", Version: "3.1"},
	}}
	app := func(name, version string) inventory.SoftwareComponent {
		return inventory.SoftwareComponent{Role: inventory.Application, Name: name, Version: version}
	}
	identified := func(vendor, name, version string) inventory.SoftwareComponent {
		c := app(name, version)
		c.Product = inventory.Product{Vendor: vendor, Name: name}
		return c
	}
	tests := []struct {
		name      string
		instances []instance
		want      []inventory.SoftwareComponent
	}{
		{"none", nil, nil},
		{
			"named and identified after the linked Software, not the instance",
			[]instance{{Class: "DBServer", Name: "MySQL", SoftwareID: "2"}},
			[]inventory.SoftwareComponent{identified("Oracle", "Oracle DB engine", "19c")},
		},
		{
			"Software with a blank vendor stays unidentified",
			[]instance{{Class: "OtherSoftware", Name: "Portal", SoftwareID: "7"}},
			[]inventory.SoftwareComponent{app("Internal portal", "3.1")},
		},
		{
			"no linked Software keeps the instance name and stays unidentified",
			[]instance{{Class: "WebServer", Name: "Apache", SoftwareID: blankKey}},
			[]inventory.SoftwareComponent{app("Apache", "")},
		},
		{
			"Software deleted since the CI was read keeps the instance name and stays unidentified",
			[]instance{{Class: "DBServer", Name: "MySQL", SoftwareID: "99"}},
			[]inventory.SoftwareComponent{app("MySQL", "")},
		},
		{
			"one per instance",
			[]instance{
				{Class: "DBServer", Name: "MySQL", SoftwareID: "2"},
				{Class: "OtherSoftware", Name: "OpenSSH", SoftwareID: "5"},
				{Class: "WebServer", Name: "IIS", SoftwareID: blankKey},
			},
			[]inventory.SoftwareComponent{
				identified("Oracle", "Oracle DB engine", "19c"),
				identified("OpenBSD", "OpenSSH", "9.6p1"),
				app("IIS", ""),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := applications(ci{Instances: tt.instances}, lk); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("applications = %+v, want %+v", got, tt.want)
			}
		})
	}
}
