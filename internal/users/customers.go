package users

import (
	"context"

	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

type StoredCustomer = postgres.StoredCustomer

var (
	ErrCustomerNotFound  = postgres.ErrCustomerNotFound
	ErrCustomerNameTaken = postgres.ErrCustomerNameTaken
)

// CreateCustomer creates a Customer together with its first Customer Admin,
// who is invited by email. Neither is stored without the other.
func (s *Service) CreateCustomer(ctx context.Context, caller tenancy.User, name, adminEmail string) (StoredCustomer, error) {
	if err := caller.ManageCustomers(); err != nil {
		return StoredCustomer{}, err
	}
	c, err := tenancy.NewCustomer(tenancy.CustomerID(uuid.New()), name)
	if err != nil {
		return StoredCustomer{}, err
	}
	admin, err := tenancy.NewUser(tenancy.UserID(uuid.New()), adminEmail, tenancy.CustomerAdmin, c.ID())
	if err != nil {
		return StoredCustomer{}, err
	}
	var stored StoredCustomer
	err = s.invite(ctx, admin, func(tx *postgres.Tx) (err error) {
		stored, err = tx.CreateCustomer(ctx, c)
		return err
	})
	return stored, err
}

func (s *Service) Customers(ctx context.Context, caller tenancy.User) ([]StoredCustomer, error) {
	if err := caller.ManageCustomers(); err != nil {
		return nil, err
	}
	var customers []StoredCustomer
	err := s.db.InTx(ctx, func(tx *postgres.Tx) (err error) {
		customers, err = tx.Customers(ctx)
		return err
	})
	return customers, err
}

func (s *Service) RenameCustomer(ctx context.Context, caller tenancy.User, id tenancy.CustomerID, name string) (StoredCustomer, error) {
	if err := caller.ManageCustomers(); err != nil {
		return StoredCustomer{}, err
	}
	c, err := tenancy.NewCustomer(id, name)
	if err != nil {
		return StoredCustomer{}, err
	}
	var stored StoredCustomer
	err = s.db.InTx(ctx, func(tx *postgres.Tx) (err error) {
		stored, err = tx.RenameCustomer(ctx, c)
		return err
	})
	return stored, err
}

// DeactivateCustomer makes the Customer a Deactivated Customer: its Users can
// no longer sign in and its CMDB Source is no longer synced. Its Users stay
// enabled in Cognito and its CMDB Source stays connected, so reactivating it
// restores both as they were (ADR 0013). Deactivating a Deactivated Customer
// keeps the time it was first deactivated.
func (s *Service) DeactivateCustomer(ctx context.Context, caller tenancy.User, id tenancy.CustomerID) (StoredCustomer, error) {
	return s.setDeactivated(ctx, caller, id, true)
}

func (s *Service) ReactivateCustomer(ctx context.Context, caller tenancy.User, id tenancy.CustomerID) (StoredCustomer, error) {
	return s.setDeactivated(ctx, caller, id, false)
}

func (s *Service) setDeactivated(ctx context.Context, caller tenancy.User, id tenancy.CustomerID, deactivated bool) (StoredCustomer, error) {
	if err := caller.ManageCustomers(); err != nil {
		return StoredCustomer{}, err
	}
	var stored StoredCustomer
	err := s.db.InTx(ctx, func(tx *postgres.Tx) (err error) {
		stored, err = tx.SetCustomerDeactivated(ctx, id, deactivated)
		return err
	})
	return stored, err
}
