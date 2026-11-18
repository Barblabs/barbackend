package stixext

import (
	"github.com/TcM1911/stix2"
)

func decodeExtension[T any](v *stix2.Vulnerability, id stix2.Identifier) (T, bool) {
	return decode[T](v.Extensions, id)
}
