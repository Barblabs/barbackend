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

func (Provider) ParseSettings(settings, credentials json.RawMessage) (cmdb.Settings, error) {
	return parseSettings(settings, credentials)
}

func (Provider) Describe(settings json.RawMessage) (cmdb.Description, error) {
	doc, _, err := parseSettingsDocument(settings)
	if err != nil {
		return cmdb.Description{}, err
	}
	return cmdb.Description{URL: doc.URL, User: doc.Auth.User}, nil
}

func (s settings) Snapshot(ctx context.Context) (inventory.Snapshot, error) {
	cis, lk, err := fetch(ctx, rest.New(s.baseURL, s.auth, rest.Options{}))
	if err != nil {
		return inventory.Snapshot{}, err
	}
	return snapshot(cis, lk), nil
}
