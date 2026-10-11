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

// retiredStatus is the only iTop status reported as retired (ADR 0005):
// implementation, stock and the rest are still part of the environment.
const retiredStatus = "obsolete"

// snapshot maps each ci to a Record, or to a Skipped Record when it holds a
// value the mapping cannot interpret or the domain rejects.
func snapshot(cis []ci, lk lookups) inventory.Snapshot {
	var s inventory.Snapshot
	for _, c := range cis {
		imported, err := importedAsset(c, lk)
		if err != nil {
			s.Skipped = append(s.Skipped, inventory.SkippedRecord{RecordID: c.key, Reason: err.Error()})
			continue
		}
		s.Records = append(s.Records, inventory.Record{RecordID: c.key, Imported: imported})
	}
	return s
}

func importedAsset(c ci, lk lookups) (inventory.ImportedAsset, error) {
	kind, ok := kinds[c.class]
	if !ok {
		return inventory.ImportedAsset{}, fmt.Errorf("class %s is not imported", c.class)
	}
	crit, err := criticality(c.criticality)
	if err != nil {
		return inventory.ImportedAsset{}, err
	}
	var components []inventory.SoftwareComponent
	if system, ok := operatingSystem(c, lk); ok {
		components = append(components, system)
	}
	components = append(components, applications(c, lk)...)
	return inventory.NewImportedAsset(inventory.ImportedAssetParams{
		Name:        c.name,
		Description: c.description,
		Kind:        kind,
		Hardware:    hardware(c, kind),
		Software:    components,
		Criticality: crit,
		Owner:       owner(c, lk),
		Retired:     c.status == retiredStatus,
	})
}

// criticality refuses a value outside iTop's defaults rather than guessing:
// a customized enum could rank a value differently than its name suggests.
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
	return inventory.Hardware{Vendor: c.brand, Model: c.model}
}

// operatingSystem names a Network Device's OS after its IOSVersion's brand,
// because iTop has no OS family for network devices (ADR 0002).
func operatingSystem(c ci, lk lookups) (inventory.SoftwareComponent, bool) {
	name, version := c.osFamily, c.osVersion
	if c.class == "NetworkDevice" {
		ios := lk.iosVersions[c.iosVersionID]
		name, version = ios.brand, ios.version
	}
	if blank(name) {
		return inventory.SoftwareComponent{}, false
	}
	return inventory.SoftwareComponent{Role: inventory.OperatingSystem, Name: name, Version: version}, true
}
