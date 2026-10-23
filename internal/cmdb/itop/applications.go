package itop

import "barbackend/internal/inventory"

func applications(c ci, lk lookups) []inventory.SoftwareComponent {
	var apps []inventory.SoftwareComponent
	for _, in := range c.Instances {
		apps = append(apps, application(in, lk))
	}
	return apps
}

func application(in instance, lk lookups) inventory.SoftwareComponent {
	if linked, ok := lk.software[in.SoftwareID]; ok {
		return inventory.SoftwareComponent{Role: inventory.Application, Name: linked.Name, Version: linked.Version}
	}
	return inventory.SoftwareComponent{Role: inventory.Application, Name: in.Name}
}
