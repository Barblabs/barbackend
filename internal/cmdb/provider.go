// Package cmdb is the seam every CMDB Provider adapter implements (ADR 0007).
package cmdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"barbackend/internal/inventory"
)

// Provider is the adapter of one CMDB Provider.
type Provider interface {
	// ParseSettings validates a CMDB Source's connection settings and its
	// decrypted credentials, both of which only the adapter can parse. It does
	// no I/O, so a source can be validated without reaching its CMDB.
	ParseSettings(settings, credentials json.RawMessage) (Settings, error)
	// Describe reads what identifies a CMDB Source to a person from its
	// plain settings alone, so showing a source never opens its credentials.
	Describe(settings json.RawMessage) (Description, error)
	// FromLogin builds the settings and credentials of a CMDB Source from a
	// login typed in the dashboard. ParseSettings still validates them.
	FromLogin(login Login) (settings, credentials json.RawMessage, err error)
}

// Login is how an admin connects a CMDB Source from the dashboard: the same
// shape for every CMDB Provider, so adding one does not change the API.
type Login struct {
	URL      string
	User     string
	Password string
}

// Description identifies a CMDB Source to a person. It holds no secret.
type Description struct {
	URL string
	// User is empty when the source authenticates without one, such as with
	// a token.
	User string
}

// Settings are the parsed connection settings of one CMDB Source. Only
// parsing produces them, so no Sync can snapshot unvalidated settings.
type Settings interface {
	// CheckCredentials makes one cheap authenticated call to the CMDB. It
	// returns a *Failure when the CMDB cannot be reached or rejects the
	// credentials, and any other error only when the check itself failed.
	// Snapshot reports the same failures the same way.
	CheckCredentials(ctx context.Context) error
	// Snapshot returns every in-scope record of the CMDB Source, or an error
	// if it could not read them all: a partial snapshot would deactivate the
	// Assets it missed (ADR 0005).
	Snapshot(ctx context.Context) (inventory.Snapshot, error)
}

// FailureCode is a stable reason a CMDB could not be used, which the
// dashboard translates. Adapters may add their own codes.
type FailureCode string

const (
	// Unreachable covers DNS failures, refused connections and timeouts.
	Unreachable        FailureCode = "unreachable"
	TLSError           FailureCode = "tls_error"
	InvalidCredentials FailureCode = "invalid_credentials" //nolint:gosec // a failure code, not a credential
	// UnexpectedResponse is a reply the adapter cannot use: a server that is
	// not the CMDB, a malformed reply, or an error the CMDB reports for a
	// reason other than the login.
	UnexpectedResponse FailureCode = "unexpected_response"
)

// Failure is why a CMDB could not be used. Message is readable on its own,
// so the dashboard can show it for a code it does not know yet.
type Failure struct {
	Code    FailureCode
	Message string
}

func (f *Failure) Error() string { return f.Message }

var ErrUnknownProvider = errors.New("unknown cmdb provider")

type Providers map[inventory.CMDBProvider]Provider

func (ps Providers) Lookup(name inventory.CMDBProvider) (Provider, error) {
	p, ok := ps[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, name)
	}
	return p, nil
}
