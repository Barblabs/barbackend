package itop

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
)

// errNotImplemented is scaffold, removed once fetch lands.
var errNotImplemented = errors.New("itop: not implemented")

type client struct {
	baseURL *url.URL
	creds   credentials
}

func newClient(baseURL *url.URL, creds credentials) *client {
	return &client{baseURL: baseURL, creds: creds}
}

// query is one core/get call: every object of class matching oql, with only
// the given output fields.
//
//nolint:unused // scaffold, read once the client lands
type query struct {
	class  string
	oql    string
	fields []string
}

//nolint:unused // scaffold, read once the client lands
type object struct {
	key    string
	class  string
	fields json.RawMessage
}

//nolint:unused // scaffold
func (c *client) get(ctx context.Context, q query) ([]object, error) {
	return nil, errNotImplemented
}
