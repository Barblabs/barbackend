package itop

import "barbackend/internal/inventory"

func applications(c ci, lk lookups) []inventory.SoftwareComponent {
	var apps []inventory.SoftwareComponent
	for _, in := range c.Instances {
		app := inventory.SoftwareComponent{Role: inventory.Application, Name: in.Name}
		if sw, ok := lk.software[in.SoftwareID]; ok {
			app.Name, app.Version = sw.Name, sw.Version
		}
		apps = append(apps, app)
	}
	return apps
}
