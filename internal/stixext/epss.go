package stixext

import (
	"encoding/json"

	"github.com/TcM1911/stix2"
)

// EPSS is the epss/1 property extension of a Vulnerability.
type EPSS struct {
	ExtensionType string  `json:"extension_type"`
	Probability   float64 `json:"probability"`
	Percentile    float64 `json:"percentile"`
	ScoreDate     string  `json:"score_date"`
	ModelVersion  string  `json:"model_version,omitempty"`
}

// NewEPSS returns e as a property extension.
func NewEPSS(e EPSS) EPSS {
	e.ExtensionType = "property-extension"
	return e
}

// EPSSOf decodes the epss/1 extension of v.
func EPSSOf(v *stix2.Vulnerability) (EPSS, bool) {
	raw, ok := v.Extensions[string(EPSSDefinitionID)]
	if !ok {
		return EPSS{}, false
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return EPSS{}, false
	}
	var e EPSS
	if err := json.Unmarshal(data, &e); err != nil {
		return EPSS{}, false
	}
	return e, true
}
