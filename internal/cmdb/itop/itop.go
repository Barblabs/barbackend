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

func (Provider) FromLogin(login cmdb.Login) (json.RawMessage, json.RawMessage, error) {
	settings, err := json.Marshal(settingsDocument{URL: login.URL, Auth: authDocument{Mode: basicAuth, User: login.User}})
	if err != nil {
		return nil, nil, err
	}
	credentials, err := json.Marshal(credentialsDocument{Password: login.Password}) //nolint:gosec // serialized only to be sealed by the service
	if err != nil {
		return nil, nil, err
	}
	return settings, credentials, nil
}

func (s settings) Snapshot(ctx context.Context) (inventory.Snapshot, error) {
	cis, lk, err := fetch(ctx, rest.New(s.baseURL, s.auth, rest.Options{}))
	if err != nil {
		return inventory.Snapshot{}, s.classify(err)
	}
	return snapshot(cis, lk), nil
}
