package itop

import "barbackend/internal/inventory"

// applications names each instance after its linked Software, because
// instance names are free text that can contradict it (an instance named
// "MySQL" linked to "Oracle DB engine"). An instance linked to no Software
// keeps its own name and no version, so it stays visible as an Unidentified
// Component (ADR 0002).
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
