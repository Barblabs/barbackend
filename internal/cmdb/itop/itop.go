// Package itop is the CMDB Provider adapter for iTop (ADR 0007). It reads
// Servers, Virtual Machines, PCs and Network Devices through the REST API.
package itop

import (
	"context"
	"encoding/json"

	"barbackend/internal/cmdb"
	"barbackend/internal/cmdb/itop/rest"
	"barbackend/internal/inventory"
)

type Provider struct{}

func (Provider) ParseSettings(raw json.RawMessage) (cmdb.Settings, error) {
	return parseSettings(raw)
}

func (s settings) Snapshot(ctx context.Context) (inventory.Snapshot, error) {
	auth, err := s.auth.auth()
	if err != nil {
		return inventory.Snapshot{}, err
	}
	cis, lk, err := fetch(ctx, rest.New(s.baseURL, auth, rest.Options{}))
	if err != nil {
		return inventory.Snapshot{}, err
	}
	return snapshot(cis, lk), nil
}
