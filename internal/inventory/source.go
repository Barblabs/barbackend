package inventory

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

var ErrInvalidCMDBSource = errors.New("invalid cmdb source")

type CustomerID uuid.UUID

func (id CustomerID) String() string { return uuid.UUID(id).String() }

type CMDBSourceID uuid.UUID

func (id CMDBSourceID) String() string { return uuid.UUID(id).String() }

type CMDBProvider string

type CMDBSource struct {
	id       CMDBSourceID
	customer CustomerID
	provider CMDBProvider
}

func NewCMDBSource(id CMDBSourceID, customer CustomerID, provider CMDBProvider) (CMDBSource, error) {
	switch {
	case id == CMDBSourceID{}:
		return CMDBSource{}, fmt.Errorf("%w: zero id", ErrInvalidCMDBSource)
	case customer == CustomerID{}:
		return CMDBSource{}, fmt.Errorf("%w: zero customer", ErrInvalidCMDBSource)
	case blank(string(provider)):
		return CMDBSource{}, fmt.Errorf("%w: empty provider", ErrInvalidCMDBSource)
	}
	return CMDBSource{id: id, customer: customer, provider: provider}, nil
}

func (s CMDBSource) ID() CMDBSourceID { return s.id }

func (s CMDBSource) Customer() CustomerID { return s.customer }

func (s CMDBSource) Provider() CMDBProvider { return s.provider }
