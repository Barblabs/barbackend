package inventory_test

import (
	"errors"
	"testing"

	"barbackend/internal/inventory"
	"github.com/google/uuid"
)

func TestNewCMDBSource(t *testing.T) {
	customerID := inventory.CustomerID(uuid.New())
	tests := []struct {
		name     string
		id       inventory.CMDBSourceID
		customer inventory.CustomerID
		provider inventory.CMDBProvider
		want     error
	}{
		{"valid", sourceID, customerID, "p", nil},
		{"zero id", inventory.CMDBSourceID{}, customerID, "p", inventory.ErrInvalidCMDBSource},
		{"zero customer", sourceID, inventory.CustomerID{}, "p", inventory.ErrInvalidCMDBSource},
		{"blank provider", sourceID, customerID, "\t", inventory.ErrInvalidCMDBSource},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := inventory.NewCMDBSource(tt.id, tt.customer, tt.provider)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if err == nil && (s.ID() != tt.id || s.Customer() != tt.customer || s.Provider() != tt.provider) {
				t.Errorf("source = %+v, want %s/%s/%s", s, tt.id, tt.customer, tt.provider)
			}
		})
	}
}
