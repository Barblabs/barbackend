// Package cmdbtest is a fake CMDB Provider for tests of the layers above the
// seam.
package cmdbtest

import (
	"context"
	"encoding/json"
	"errors"

	"barbackend/internal/cmdb"
	"barbackend/internal/inventory"
)

// Name is the CMDB Provider the fake is registered as.
const Name inventory.CMDBProvider = "fake"

var (
	ErrInvalidSettings    = errors.New("settings need a url")
	ErrInvalidCredentials = errors.New("credentials need a secret")
)

// Settings and Credentials are valid for the fake, with Secret as the secret.
const (
	Settings    = `{"url": "http://cmdb", "user": "admin"}`
	Credentials = `{"secret": "` + Secret + `"}`
	Secret      = "hunter2"
)

// Provider returns whatever snapshot or error the test sets, and keeps the
// secret it last parsed.
type Provider struct {
	Snapshot inventory.Snapshot
	Err      error
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

func (p *Provider) ParseSettings(settings, credentials json.RawMessage) (cmdb.Settings, error) {
	if _, err := p.Describe(settings); err != nil {
		return nil, err
	}
	var c struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(credentials, &c); err != nil || c.Secret == "" {
		return nil, ErrInvalidCredentials
	}
	p.Secret = c.Secret
	return snapshotter{p}, nil
}

func (p *Provider) Describe(settings json.RawMessage) (cmdb.Description, error) {
	var s settingsDocument
	if err := json.Unmarshal(settings, &s); err != nil || s.URL == "" {
		return cmdb.Description{}, ErrInvalidSettings
	}
	return cmdb.Description{URL: s.URL, User: s.User}, nil
}

type snapshotter struct{ p *Provider }

func (s snapshotter) Snapshot(context.Context) (inventory.Snapshot, error) {
	return s.p.Snapshot, s.p.Err
}
