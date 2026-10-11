// Package cmdb is the seam every CMDB Provider adapter implements (ADR 0007).
package cmdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"barbackend/internal/inventory"
)

// Provider is the adapter of one CMDB Provider.
type Provider interface {
	// ParseSettings validates a CMDB Source's connection settings, which only
	// the adapter can parse. It does no I/O and reads no secrets, so a source
	// can be validated by a process that will never sync it.
	ParseSettings(settings json.RawMessage) (Settings, error)
}

// Settings are the parsed connection settings of one CMDB Source. Only
// parsing produces them, so no Sync can snapshot unvalidated settings.
type Settings interface {
	// Snapshot returns every in-scope record of the CMDB Source, or an error
	// if it could not read them all: a partial snapshot would deactivate the
	// Assets it missed (ADR 0005).
	Snapshot(ctx context.Context) (inventory.Snapshot, error)
}

var ErrUnknownProvider = errors.New("unknown cmdb provider")

type Providers map[inventory.CMDBProvider]Provider

func (ps Providers) Lookup(name inventory.CMDBProvider) (Provider, error) {
	p, ok := ps[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, name)
	}
	return p, nil
}
