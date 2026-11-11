package feeds

import (
	"context"

	"github.com/TcM1911/stix2"
)

// Emit hands one normalized object to the caller.
type Emit func(stix2.STIXObject) error

// Pull reads a Feed, emitting each normalized object until the Feed is exhausted or emit fails.
type Pull func(ctx context.Context, emit Emit) error

// Lookup reads what a Feed says about one CVE, returning nil when the Feed does not list it.
type Lookup func(ctx context.Context, cveID string) (*stix2.Vulnerability, error)
