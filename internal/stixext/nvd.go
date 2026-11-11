package stixext

import "github.com/TcM1911/stix2"

// NVD is the nvd/1 property extension of a Vulnerability (ADR 0010).
type NVD struct {
	ExtensionType string     `json:"extension_type"`
	Published     string     `json:"published"`
	LastModified  string     `json:"last_modified"`
	VulnStatus    string     `json:"vuln_status"`
	CVSS          []CVSS     `json:"cvss"`
	CWEs          []string   `json:"cwes"`
	Affected      []Affected `json:"affected"`
	// CNAAffected is what the CVE's numbering authority lists, which NVD relays
	// even for a CVE it has not analyzed and so gave no CPE matches.
	CNAAffected []CNAAffected `json:"cna_affected,omitempty"`
}

// CVSS is one metric NVD reports for a Vulnerability.
type CVSS struct {
	Version   string  `json:"version"`
	BaseScore float64 `json:"base_score"`
	Vector    string  `json:"vector"`
	Source    string  `json:"source"`
	Type      string  `json:"type"`
}

// Affected is one vulnerable CPE match of a Vulnerability. Version and Update
// are the version and update fields of Criteria: an exact version, "*" for any
// (bounded by the range, if any) or "-" for none. Entries stored before they
// were added have neither.
type Affected struct {
	Criteria              string `json:"criteria"`
	Vendor                string `json:"vendor"`
	Product               string `json:"product"`
	Version               string `json:"version,omitempty"`
	Update                string `json:"update,omitempty"`
	VersionStartIncluding string `json:"version_start_including,omitempty"`
	VersionStartExcluding string `json:"version_start_excluding,omitempty"`
	VersionEndIncluding   string `json:"version_end_including,omitempty"`
	VersionEndExcluding   string `json:"version_end_excluding,omitempty"`
}

// CNAAffected is one product a CVE's numbering authority lists as affected.
type CNAAffected struct {
	Source        string       `json:"source"`
	Vendor        string       `json:"vendor"`
	Product       string       `json:"product"`
	DefaultStatus string       `json:"default_status"`
	Versions      []CNAVersion `json:"versions"`
}

// CNAVersion is a version or range of a CNAAffected, as the authority wrote it.
type CNAVersion struct {
	Version         string `json:"version"`
	LessThan        string `json:"less_than,omitempty"`
	LessThanOrEqual string `json:"less_than_or_equal,omitempty"`
	Status          string `json:"status"`
}

// NewNVD returns n as a property extension.
func NewNVD(n NVD) NVD {
	n.ExtensionType = "property-extension"
	return n
}

// NVDOf decodes the nvd/1 extension of v.
func NVDOf(v *stix2.Vulnerability) (NVD, bool) {
	return decodeExtension[NVD](v, NVDDefinitionID)
}
