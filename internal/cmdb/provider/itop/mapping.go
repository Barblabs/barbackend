package itop

import (
	"fmt"
	"strings"

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

// exposures maps the Locations a Customer keeps in iTop to record Exposure
// (ADR 0021). Any other Location is Unknown.
var exposures = map[string]inventory.Exposure{
	"exposed":     inventory.InternetFacing,
	"not exposed": inventory.Internal,
}

// lifecycles maps the iTop status to a Lifecycle Stage (ADR 0028). Obsolete
// is Retired instead, and any other status is Unknown.
var lifecycles = map[string]inventory.LifecycleStage{
	"production":     inventory.LifecycleProduction,
	"implementation": inventory.LifecycleImplementation,
	"stock":          inventory.LifecycleStock,
}

const (
	retiredStatus      = "obsolete"
	inactiveAreaStatus = "inactive"
)

func snapshot(cis []ci, orgs []organization, lk lookups) inventory.Snapshot {
	s := inventory.Snapshot{Areas: readableAreas(orgs)}
	readable := make(map[string]bool, len(s.Areas))
	for _, a := range s.Areas {
		readable[a.RecordID] = true
	}
	for _, c := range cis {
		imported, err := importedAsset(c, readable, lk)
		if err != nil {
			s.Skipped = append(s.Skipped, inventory.SkippedRecord{RecordID: c.Key, Reason: err.Error()})
			continue
		}
		s.Records = append(s.Records, inventory.Record{RecordID: c.Key, Imported: imported})
	}
	return s
}

func readableAreas(orgs []organization) []inventory.AreaRecord {
	var areas []inventory.AreaRecord
	for _, org := range orgs {
		imported, err := inventory.NewImportedArea(inventory.ImportedAreaParams{
			Name:     org.Name,
			Inactive: org.Status == inactiveAreaStatus,
		})
		if err != nil {
			continue
		}
		areas = append(areas, inventory.AreaRecord{RecordID: org.Key, Imported: imported})
	}
	return areas
}

func importedAsset(c ci, readableAreas map[string]bool, lk lookups) (inventory.ImportedAsset, error) {
	if !readableAreas[c.OrgID] {
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
		Exposure:    exposures[strings.ToLower(strings.TrimSpace(c.Location))],
		Lifecycle:   lifecycles[strings.ToLower(strings.TrimSpace(c.Status))],
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
