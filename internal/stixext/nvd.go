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
}

type CVSS struct {
	Version   string  `json:"version"`
	BaseScore float64 `json:"base_score"`
	Vector    string  `json:"vector"`
	Source    string  `json:"source"`
	Type      string  `json:"type"`
}

type Affected struct {
	Criteria              string `json:"criteria"`
	Vendor                string `json:"vendor"`
	Product               string `json:"product"`
	VersionStartIncluding string `json:"version_start_including,omitempty"`
	VersionStartExcluding string `json:"version_start_excluding,omitempty"`
	VersionEndIncluding   string `json:"version_end_including,omitempty"`
	VersionEndExcluding   string `json:"version_end_excluding,omitempty"`
}

func NewNVD(n NVD) NVD {
	n.ExtensionType = "property-extension"
	return n
}

func NVDOf(v *stix2.Vulnerability) (NVD, bool) {
	return decodeExtension[NVD](v, NVDDefinitionID)
}
