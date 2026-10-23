package stixext

import "github.com/TcM1911/stix2"

// EPSS is the epss/1 property extension of a Vulnerability.
type EPSS struct {
	ExtensionType string  `json:"extension_type"`
	Probability   float64 `json:"probability"`
	Percentile    float64 `json:"percentile"`
	ScoreDate     string  `json:"score_date"`
	ModelVersion  string  `json:"model_version,omitempty"`
}

func NewEPSS(e EPSS) EPSS {
	e.ExtensionType = "property-extension"
	return e
}

func EPSSOf(v *stix2.Vulnerability) (EPSS, bool) {
	return decodeExtension[EPSS](v, EPSSDefinitionID)
}
