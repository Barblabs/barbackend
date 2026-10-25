package itop

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"barbackend/internal/cmdb/itop/rest"
)

var (
	ErrInvalidSettings    = errors.New("invalid itop settings")
	ErrInvalidCredentials = errors.New("invalid itop credentials")
)

type authMode string

const basicAuth authMode = "basic"

type settingsDocument struct {
	URL  string       `json:"url"`
	Auth authDocument `json:"auth"`
}

type authDocument struct {
	Mode authMode `json:"mode"`
	User string   `json:"user"`
}

type credentialsDocument struct {
	Password string `json:"password"`
}

type settings struct {
	baseURL *url.URL
	auth    rest.Auth
}

func parseSettings(rawSettings, rawCredentials json.RawMessage) (settings, error) {
	doc, base, err := parseSettingsDocument(rawSettings)
	if err != nil {
		return settings{}, err
	}
	var creds credentialsDocument
	if err := decodeStrict(rawCredentials, &creds); err != nil {
		return settings{}, fmt.Errorf("%w: %v", ErrInvalidCredentials, err)
	}
	auth, err := doc.Auth.restAuth(creds)
	if err != nil {
		return settings{}, err
	}
	return settings{baseURL: base, auth: auth}, nil
}

func parseSettingsDocument(raw json.RawMessage) (settingsDocument, *url.URL, error) {
	var doc settingsDocument
	if err := decodeStrict(raw, &doc); err != nil {
		return settingsDocument{}, nil, fmt.Errorf("%w: %v", ErrInvalidSettings, err)
	}
	base, err := parseBaseURL(doc.URL)
	if err != nil {
		return settingsDocument{}, nil, err
	}
	if err := doc.Auth.validate(); err != nil {
		return settingsDocument{}, nil, err
	}
	return doc, base, nil
}

func decodeStrict(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the object")
	}
	return nil
}

func parseBaseURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("%w: url: %v", ErrInvalidSettings, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("%w: url %q is not an absolute http or https URL", ErrInvalidSettings, s)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: url has credentials, pass them as credentials instead", ErrInvalidSettings)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: url %q has a query or fragment", ErrInvalidSettings, s)
	}
	return u, nil
}

func (a authDocument) validate() error {
	if a.Mode != basicAuth {
		return fmt.Errorf("%w: auth mode %q is not basic", ErrInvalidSettings, a.Mode)
	}
	if blank(a.User) {
		return fmt.Errorf("%w: basic auth needs user", ErrInvalidSettings)
	}
	return nil
}

func (a authDocument) restAuth(c credentialsDocument) (rest.Auth, error) {
	if c.Password == "" {
		return rest.Auth{}, fmt.Errorf("%w: basic auth needs a password", ErrInvalidCredentials)
	}
	return rest.BasicAuth(a.User, c.Password), nil
}

func blank(s string) bool { return strings.TrimSpace(s) == "" }
