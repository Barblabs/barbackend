package itop

import (
	"reflect"
	"testing"

	"barbackend/internal/inventory"
)

func TestApplications(t *testing.T) {
	lk := lookups{software: map[string]software{
		"2": {Name: "Oracle DB engine", Version: "19c"},
		"5": {Name: "OpenSSH", Version: "9.6p1"},
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
			[]instance{{Class: "DBServer", Name: "MySQL", SoftwareID: "2"}},
			[]inventory.SoftwareComponent{app("Oracle DB engine", "19c")},
		},
		{
			"no linked Software keeps the instance name",
			[]instance{{Class: "WebServer", Name: "Apache", SoftwareID: blankKey}},
			[]inventory.SoftwareComponent{app("Apache", "")},
		},
		{
			"Software deleted since the CI was read keeps the instance name",
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
			[]inventory.SoftwareComponent{app("Oracle DB engine", "19c"), app("OpenSSH", "9.6p1"), app("IIS", "")},
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
