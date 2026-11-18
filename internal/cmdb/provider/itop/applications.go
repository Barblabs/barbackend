package itop

import "barbackend/internal/inventory"

func applications(c ci, lk lookups) []inventory.SoftwareComponent {
	var apps []inventory.SoftwareComponent
	for _, in := range c.Instances {
		app := inventory.SoftwareComponent{Role: inventory.Application, Name: in.Name}
		if sw, ok := lk.software[in.SoftwareID]; ok {
			app.Version = sw.Version
			if !blank(sw.Vendor) {
				app.Product = inventory.Product{Vendor: sw.Vendor, Name: sw.Name}
			}
		}
		apps = append(apps, app)
	}
	return apps
}
