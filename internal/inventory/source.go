package inventory

import (
	"errors"
	"fmt"
)

var ErrInvalidCMDBSource = errors.New("invalid cmdb source")

type CustomerID string

// Assets carry no Customer: it is reached through the CMDB Source.
type CMDBSourceID string

// CMDBProvider names the adapter that reads a CMDB Source; the domain never
// interprets it, so adding a provider needs no change here.
type CMDBProvider string

// CMDBSource holds no connection settings: their shape is provider-specific
// and only the provider's adapter reads them.
type CMDBSource struct {
	id       CMDBSourceID
	customer CustomerID
	provider CMDBProvider
}

func NewCMDBSource(id CMDBSourceID, customer CustomerID, provider CMDBProvider) (CMDBSource, error) {
	switch {
	case blank(string(id)):
		return CMDBSource{}, fmt.Errorf("%w: empty id", ErrInvalidCMDBSource)
	case blank(string(customer)):
		return CMDBSource{}, fmt.Errorf("%w: empty customer", ErrInvalidCMDBSource)
	case blank(string(provider)):
		return CMDBSource{}, fmt.Errorf("%w: empty provider", ErrInvalidCMDBSource)
	}
	return CMDBSource{id: id, customer: customer, provider: provider}, nil
}

func (s CMDBSource) ID() CMDBSourceID { return s.id }

func (s CMDBSource) Customer() CustomerID { return s.customer }

func (s CMDBSource) Provider() CMDBProvider { return s.provider }
