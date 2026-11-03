package itop

import (
	"strings"

	"barbackend/internal/inventory"
)

func applications(c ci, lk lookups) []inventory.SoftwareComponent {
	var apps []inventory.SoftwareComponent
	for _, in := range c.Instances {
		app := inventory.SoftwareComponent{Role: inventory.Application, Name: in.Name}
		if sw, ok := lk.software[in.SoftwareID]; ok {
			app.Name, app.Version = sw.Name, sw.Version
			app.Product = product(sw)
		}
		apps = append(apps, app)
	}
	return apps
}

// product leaves a Software with a blank vendor or name unidentified, because
// inventory rejects a half Product and that would skip the whole Asset.
func product(sw software) inventory.Product {
	if strings.TrimSpace(sw.Vendor) == "" || strings.TrimSpace(sw.Name) == "" {
		return inventory.Product{}
	}
	return inventory.Product{Vendor: sw.Vendor, Name: sw.Name}
}
