package stixext

import (
	"encoding/json"

	"github.com/TcM1911/stix2"
)

func decodeExtension[T any](v *stix2.Vulnerability, id stix2.Identifier) (T, bool) {
	var zero T
	raw, ok := v.Extensions[string(id)]
	if !ok {
		return zero, false
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return zero, false
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		return zero, false
	}
	return out, true
}
