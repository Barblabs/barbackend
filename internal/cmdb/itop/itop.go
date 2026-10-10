// Package itop is the CMDB Provider adapter for iTop (ADR 0007). It reads
// Servers, Virtual Machines, PCs and Network Devices through the REST API.
package itop

import (
	"context"
	"encoding/json"

	"barbackend/internal/inventory"
)

type Provider struct{}

func (Provider) ValidateSettings(raw json.RawMessage) error {
	_, err := parseSettings(raw)
	return err
}

func (Provider) Snapshot(ctx context.Context, raw json.RawMessage) (inventory.Snapshot, error) {
	s, err := parseSettings(raw)
	if err != nil {
		return inventory.Snapshot{}, err
	}
	creds, err := s.auth.credentials()
	if err != nil {
		return inventory.Snapshot{}, err
	}
	cis, lk, err := fetch(ctx, newClient(s.baseURL, creds))
	if err != nil {
		return inventory.Snapshot{}, err
	}
	return snapshot(cis, lk), nil
}
