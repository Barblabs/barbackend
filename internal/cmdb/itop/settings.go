package itop

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"barbackend/internal/cmdb/itop/rest"
)

var (
	ErrInvalidSettings = errors.New("invalid itop settings")
	ErrMissingSecret   = errors.New("itop secret is not set")
)

type authMode string

const (
	basicAuth authMode = "basic"
	tokenAuth authMode = "token"
)

// settingsDocument is the JSON stored on the CMDB Source. Secrets are never
// stored: it names the environment variables that hold them.
type settingsDocument struct {
	URL  string       `json:"url"`
	Auth authDocument `json:"auth"`
}

type authDocument struct {
	Mode        authMode `json:"mode"`
	User        string   `json:"user"`
	PasswordEnv string   `json:"password_env"`
	TokenEnv    string   `json:"token_env"`
}

type settings struct {
	baseURL *url.URL
	auth    authDocument
}

// parseSettings rejects unknown fields so that a typo in an optional-looking
// field fails when the source is added, not as a puzzling auth error later.
func parseSettings(raw json.RawMessage) (settings, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc settingsDocument
	if err := dec.Decode(&doc); err != nil {
		return settings{}, fmt.Errorf("%w: %v", ErrInvalidSettings, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return settings{}, fmt.Errorf("%w: data after the settings object", ErrInvalidSettings)
	}
	base, err := parseBaseURL(doc.URL)
	if err != nil {
		return settings{}, err
	}
	if err := doc.Auth.validate(); err != nil {
		return settings{}, err
	}
	return settings{baseURL: base, auth: doc.Auth}, nil
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
		return nil, fmt.Errorf("%w: url has credentials, name them in auth instead", ErrInvalidSettings)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: url %q has a query or fragment", ErrInvalidSettings, s)
	}
	return u, nil
}

func (a authDocument) validate() error {
	switch a.Mode {
	case basicAuth:
		if blank(a.User) || blank(a.PasswordEnv) {
			return fmt.Errorf("%w: basic auth needs user and password_env", ErrInvalidSettings)
		}
		if a.TokenEnv != "" {
			return fmt.Errorf("%w: basic auth does not take token_env", ErrInvalidSettings)
		}
	case tokenAuth:
		if blank(a.TokenEnv) {
			return fmt.Errorf("%w: token auth needs token_env", ErrInvalidSettings)
		}
		if a.User != "" || a.PasswordEnv != "" {
			return fmt.Errorf("%w: token auth does not take user or password_env", ErrInvalidSettings)
		}
	default:
		return fmt.Errorf("%w: auth mode %q is not basic or token", ErrInvalidSettings, a.Mode)
	}
	return nil
}

// auth reads the secrets at Sync time rather than in ValidateSettings,
// because the process adding a source is not the one that syncs it.
func (a authDocument) auth() (rest.Auth, error) {
	if a.Mode == basicAuth {
		password, err := secret(a.PasswordEnv)
		return rest.BasicAuth(a.User, password), err
	}
	token, err := secret(a.TokenEnv)
	return rest.TokenAuth(token), err
}

func secret(env string) (string, error) {
	v := os.Getenv(env)
	if v == "" {
		return "", fmt.Errorf("%w: %s", ErrMissingSecret, env)
	}
	return v, nil
}

func blank(s string) bool { return strings.TrimSpace(s) == "" }
