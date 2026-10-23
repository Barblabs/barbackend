package feeds

import (
	"context"

	"github.com/TcM1911/stix2"
)

type Emit func(stix2.STIXObject) error

// Pull reads a Feed, emitting each normalized object until the Feed is exhausted or emit fails.
type Pull func(ctx context.Context, emit Emit) error
