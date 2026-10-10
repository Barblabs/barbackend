// Package cmdb syncs CMDB Sources through the adapter of their CMDB Provider
// (ADR 0007).
package cmdb

import (
	"context"
	"encoding/json"

	"barbackend/internal/inventory"
)

// Provider is the adapter of one CMDB Provider. Settings are the CMDB
// Source's connection settings, which only the adapter can parse.
type Provider interface {
	ValidateSettings(settings json.RawMessage) error
	// Snapshot returns every in-scope record of the CMDB Source, or an error
	// if it could not read them all: a partial snapshot would deactivate the
	// Assets it missed (ADR 0005).
	Snapshot(ctx context.Context, settings json.RawMessage) (inventory.Snapshot, error)
}

type Providers map[inventory.CMDBProvider]Provider
