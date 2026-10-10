package itop

import (
	"context"
	"errors"

	"barbackend/internal/cmdb/itop/rest"
)

// errNotImplemented is scaffold, removed once fetch lands.
var errNotImplemented = errors.New("itop: not implemented")

func fetch(ctx context.Context, c *rest.Client) ([]ci, lookups, error) {
	return nil, lookups{}, errNotImplemented
}
