package itop

import (
	"fmt"

	"barbackend/internal/inventory"
)

var kinds = map[string]inventory.AssetKind{
	"Server":         inventory.Server,
	"VirtualMachine": inventory.VirtualMachine,
	"PC":             inventory.Workstation,
	"NetworkDevice":  inventory.NetworkDevice,
}

var criticalities = map[string]inventory.Criticality{
	"high":   inventory.CriticalityHigh,
	"medium": inventory.CriticalityMedium,
	"low":    inventory.CriticalityLow,
}

const (
	retiredStatus      = "obsolete"
	inactiveAreaStatus = "inactive"
)

func snapshot(cis []ci, orgs []organization, lk lookups) inventory.Snapshot {
	var s inventory.Snapshot
	areas := map[string]bool{}
	for _, org := range orgs {
		imported, err := inventory.NewImportedArea(inventory.ImportedAreaParams{
			Name:     org.Name,
			Inactive: org.Status == inactiveAreaStatus,
		})
		// An Organization the domain rejects is left out, so its CIs are
		// skipped below instead of failing the whole Sync.
		if err != nil {
			continue
		}
		areas[org.Key] = true
		s.Areas = append(s.Areas, inventory.AreaRecord{RecordID: org.Key, Imported: imported})
	}
	for _, c := range cis {
		imported, err := importedAsset(c, areas, lk)
		if err != nil {
			s.Skipped = append(s.Skipped, inventory.SkippedRecord{RecordID: c.Key, Reason: err.Error()})
			continue
		}
		s.Records = append(s.Records, inventory.Record{RecordID: c.Key, Imported: imported})
	}
	return s
}

// importedAsset fails for a ci whose Organization is not among the Areas, so
// it is skipped rather than imported without its Area (ADR 0007).
func importedAsset(c ci, areas map[string]bool, lk lookups) (inventory.ImportedAsset, error) {
	if !areas[c.OrgID] {
		return inventory.ImportedAsset{}, fmt.Errorf("organization %s is not readable", c.OrgID)
	}
	kind, ok := kinds[c.Class]
	if !ok {
		return inventory.ImportedAsset{}, fmt.Errorf("class %s is not imported", c.Class)
	}
	crit, err := criticality(c.Criticality)
	if err != nil {
		return inventory.ImportedAsset{}, err
	}
	var components []inventory.SoftwareComponent
	if system, ok := operatingSystem(c, lk); ok {
		components = append(components, system)
	}
	components = append(components, applications(c, lk)...)
	return inventory.NewImportedAsset(inventory.ImportedAssetParams{
		Name:        c.Name,
		Description: c.Description,
		Kind:        kind,
		Hardware:    hardware(c, kind),
		Software:    components,
		Criticality: crit,
		Owner:       owner(c, lk),
		Area:        c.OrgID,
		Retired:     c.Status == retiredStatus,
	})
}

func criticality(raw *string) (inventory.Criticality, error) {
	if raw == nil {
		return inventory.CriticalityUnknown, nil
	}
	crit, ok := criticalities[*raw]
	if !ok {
		return 0, fmt.Errorf("business_criticity %q is not high, medium or low", *raw)
	}
	return crit, nil
}

func hardware(c ci, kind inventory.AssetKind) inventory.Hardware {
	if !kind.Physical() {
		return inventory.Hardware{}
	}
	return inventory.Hardware{Vendor: c.Brand, Model: c.Model}
}

// operatingSystem names a Network Device's OS after its IOSVersion's brand,
// because iTop has no OS family for network devices (ADR 0002).
func operatingSystem(c ci, lk lookups) (inventory.SoftwareComponent, bool) {
	name, version := c.OSFamily, c.OSVersion
	if c.Class == "NetworkDevice" {
		ios := lk.iosVersions[c.IOSVersionID]
		name, version = ios.Brand, ios.Name
	}
	if blank(name) {
		return inventory.SoftwareComponent{}, false
	}
	return inventory.SoftwareComponent{Role: inventory.OperatingSystem, Name: name, Version: version}, true
}
