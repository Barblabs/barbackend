package itop

import (
	"reflect"
	"testing"

	"barbackend/internal/inventory"
)

func TestApplications(t *testing.T) {
	lk := lookups{software: map[string]software{
		"2": {name: "Oracle DB engine", version: "19c"},
		"5": {name: "OpenSSH", version: "9.6p1"},
	}}
	app := func(name, version string) inventory.SoftwareComponent {
		return inventory.SoftwareComponent{Role: inventory.Application, Name: name, Version: version}
	}
	tests := []struct {
		name      string
		instances []instance
		want      []inventory.SoftwareComponent
	}{
		{"none", nil, nil},
		{
			"named after the linked Software, not the instance",
			[]instance{{class: "DBServer", name: "MySQL", softwareID: "2"}},
			[]inventory.SoftwareComponent{app("Oracle DB engine", "19c")},
		},
		{
			"no linked Software keeps the instance name",
			[]instance{{class: "WebServer", name: "Apache", softwareID: blankKey}},
			[]inventory.SoftwareComponent{app("Apache", "")},
		},
		{
			"Software deleted since the CI was read keeps the instance name",
			[]instance{{class: "DBServer", name: "MySQL", softwareID: "99"}},
			[]inventory.SoftwareComponent{app("MySQL", "")},
		},
		{
			"one per instance",
			[]instance{
				{class: "DBServer", name: "MySQL", softwareID: "2"},
				{class: "OtherSoftware", name: "OpenSSH", softwareID: "5"},
				{class: "WebServer", name: "IIS", softwareID: blankKey},
			},
			[]inventory.SoftwareComponent{app("Oracle DB engine", "19c"), app("OpenSSH", "9.6p1"), app("IIS", "")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := applications(ci{instances: tt.instances}, lk); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("applications = %+v, want %+v", got, tt.want)
			}
		})
	}
}
