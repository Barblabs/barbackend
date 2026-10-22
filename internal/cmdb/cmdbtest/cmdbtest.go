// Package cmdbtest is a fake CMDB Provider for tests of the layers above the
// seam.
package cmdbtest

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"

	"barbackend/internal/cmdb"
	"barbackend/internal/inventory"
)

// Name is the CMDB Provider the fake is registered as.
const Name inventory.CMDBProvider = "fake"

var (
	ErrInvalidSettings    = errors.New("settings need an absolute url")
	ErrInvalidCredentials = errors.New("credentials need a secret")
)

// Settings and Credentials are valid for the fake, with Secret as the secret.
const (
	Settings    = `{"url": "http://cmdb", "user": "admin"}`
	Credentials = `{"secret": "` + Secret + `"}`
	Secret      = "hunter2"
)

// Provider returns whatever snapshot, error and credential check result the
// test sets, and keeps the secret it last parsed.
type Provider struct {
	Snapshot inventory.Snapshot
	Err      error
	CheckErr error
	Secret   string
}

// Providers registers p under Name.
func (p *Provider) Providers() cmdb.Providers {
	return cmdb.Providers{Name: p}
}

type settingsDocument struct {
	URL  string `json:"url"`
	User string `json:"user"`
}

type credentialsDocument struct {
	Secret string `json:"secret"`
}

func (p *Provider) ParseSettings(settings, credentials json.RawMessage) (cmdb.Settings, error) {
	if _, err := p.Describe(settings); err != nil {
		return nil, err
	}
	var c credentialsDocument
	if err := json.Unmarshal(credentials, &c); err != nil || c.Secret == "" {
		return nil, ErrInvalidCredentials
	}
	p.Secret = c.Secret
	return snapshotter{p}, nil
}

func (p *Provider) Describe(settings json.RawMessage) (cmdb.Description, error) {
	var s settingsDocument
	if err := json.Unmarshal(settings, &s); err != nil {
		return cmdb.Description{}, ErrInvalidSettings
	}
	if u, err := url.Parse(s.URL); err != nil || u.Scheme == "" || u.Host == "" {
		return cmdb.Description{}, ErrInvalidSettings
	}
	return cmdb.Description{URL: s.URL, User: s.User}, nil
}

func (p *Provider) FromLogin(login cmdb.Login) (json.RawMessage, json.RawMessage, error) {
	settings, err := json.Marshal(settingsDocument{URL: login.URL, User: login.User})
	if err != nil {
		return nil, nil, err
	}
	credentials, err := json.Marshal(credentialsDocument{Secret: login.Password}) //nolint:gosec // the service seals credentials before storing them
	if err != nil {
		return nil, nil, err
	}
	return settings, credentials, nil
}

type snapshotter struct{ p *Provider }

func (s snapshotter) CheckCredentials(context.Context) error {
	return s.p.CheckErr
}

func (s snapshotter) Snapshot(context.Context) (inventory.Snapshot, error) {
	return s.p.Snapshot, s.p.Err
}
