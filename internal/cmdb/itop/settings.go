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

const (
	basicAuth authMode = "basic"
	tokenAuth authMode = "token"
)

// settingsDocument is the plain JSON stored on the CMDB Source. It holds no
// secret: those arrive decrypted as a credentialsDocument (ADR 0012).
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
	Token    string `json:"token"`
}

type settings struct {
	baseURL *url.URL
	auth    rest.Auth
}

func parseSettings(rawSettings, rawCredentials json.RawMessage) (settings, error) {
	var doc settingsDocument
	if err := decodeStrict(rawSettings, &doc); err != nil {
		return settings{}, fmt.Errorf("%w: %v", ErrInvalidSettings, err)
	}
	base, err := parseBaseURL(doc.URL)
	if err != nil {
		return settings{}, err
	}
	if err := doc.Auth.validate(); err != nil {
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

// decodeStrict rejects unknown fields so that a typo in an optional-looking
// field fails when the source is added, not as a puzzling auth error later.
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

// parseBaseURL accepts a path because iTop is often served under one
// (http://host/itop). Settings are stored in plain text, so credentials in the
// URL are refused.
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
	switch a.Mode {
	case basicAuth:
		if blank(a.User) {
			return fmt.Errorf("%w: basic auth needs user", ErrInvalidSettings)
		}
	case tokenAuth:
		if a.User != "" {
			return fmt.Errorf("%w: token auth does not take user", ErrInvalidSettings)
		}
	default:
		return fmt.Errorf("%w: auth mode %q is not basic or token", ErrInvalidSettings, a.Mode)
	}
	return nil
}

// restAuth checks that the credentials hold exactly the secret the mode
// needs. A secret is only empty or not: spaces may be part of a password.
func (a authDocument) restAuth(c credentialsDocument) (rest.Auth, error) {
	if a.Mode == basicAuth {
		if c.Password == "" || c.Token != "" {
			return rest.Auth{}, fmt.Errorf("%w: basic auth needs a password and no token", ErrInvalidCredentials)
		}
		return rest.BasicAuth(a.User, c.Password), nil
	}
	if c.Token == "" || c.Password != "" {
		return rest.Auth{}, fmt.Errorf("%w: token auth needs a token and no password", ErrInvalidCredentials)
	}
	return rest.TokenAuth(c.Token), nil
}

func blank(s string) bool { return strings.TrimSpace(s) == "" }
