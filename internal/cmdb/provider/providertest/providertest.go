// Package providertest is a fake CMDB Provider for tests of the layers above the
// seam.
package providertest

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"

	"barbackend/internal/cmdb/provider"
	"barbackend/internal/inventory"
)

// Name is the CMDB Provider the fake is registered as.
const Name inventory.CMDBProvider = "fake"

var (
	ErrInvalidSettings    = errors.New("settings need an absolute url")
	ErrInvalidCredentials = errors.New("credentials need a secret")
)

// Secret is the password of Login.
const Secret = "hunter2"

// Login is valid for the fake.
var Login = provider.Login{URL: "http://cmdb", User: "admin", Password: Secret}

// Provider returns whatever snapshot, error and credential check result the
// test sets, and keeps the secret it last parsed.
type Provider struct {
	Snapshot inventory.Snapshot
	Err      error
	// Hanging, if set, makes Snapshot close it and wait for its context to
	// end, like a CMDB that never answers.
	Hanging chan struct{}
	// BeforeSnapshot, if set, runs at the start of Snapshot, such as to
	// disconnect the source while its Sync runs.
	BeforeSnapshot func()
	CheckErr       error
	Secret         string
}

// Providers registers p under Name.
func (p *Provider) Providers() provider.Providers {
	return provider.Providers{Name: p}
}

type settingsDocument struct {
	URL  string `json:"url"`
	User string `json:"user"`
}

type credentialsDocument struct {
	Secret string `json:"secret"`
}

func (p *Provider) ParseSettings(settings, credentials json.RawMessage) (provider.Settings, error) {
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

func (p *Provider) Describe(settings json.RawMessage) (provider.Description, error) {
	var s settingsDocument
	if err := json.Unmarshal(settings, &s); err != nil {
		return provider.Description{}, ErrInvalidSettings
	}
	if u, err := url.Parse(s.URL); err != nil || u.Scheme == "" || u.Host == "" {
		return provider.Description{}, ErrInvalidSettings
	}
	return provider.Description{URL: s.URL, User: s.User}, nil
}

func (p *Provider) FromLogin(login provider.Login) (json.RawMessage, json.RawMessage, error) {
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

func (s snapshotter) Snapshot(ctx context.Context) (inventory.Snapshot, error) {
	if s.p.BeforeSnapshot != nil {
		s.p.BeforeSnapshot()
	}
	if s.p.Hanging != nil {
		close(s.p.Hanging)
		<-ctx.Done()
		return inventory.Snapshot{}, ctx.Err()
	}
	return s.p.Snapshot, s.p.Err
}
