package stixext

import "github.com/TcM1911/stix2"

// KEV is the kev/1 property extension of a Vulnerability.
type KEV struct {
	ExtensionType              string `json:"extension_type"`
	DateAdded                  string `json:"date_added"`
	DueDate                    string `json:"due_date"`
	RequiredAction             string `json:"required_action"`
	KnownRansomwareCampaignUse string `json:"known_ransomware_campaign_use"`
	VendorProject              string `json:"vendor_project"`
	Product                    string `json:"product"`
	CatalogVersion             string `json:"catalog_version"`
	CatalogReleased            string `json:"catalog_released"`
}

func NewKEV(k KEV) KEV {
	k.ExtensionType = "property-extension"
	return k
}

func KEVOf(v *stix2.Vulnerability) (KEV, bool) {
	return decodeExtension[KEV](v, KEVDefinitionID)
}
