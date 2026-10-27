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
	return s.changeCustomer(ctx, caller, func(tx *postgres.Tx) (StoredCustomer, error) {
		c, err := tenancy.NewCustomer(id, name)
		if err != nil {
			return StoredCustomer{}, err
		}
		return tx.RenameCustomer(ctx, c)
	})
}

// DeactivateCustomer makes the Customer a Deactivated Customer: its Users can
// no longer sign in and its CMDB Source is no longer synced. Its Users stay
// enabled in Cognito and its CMDB Source stays connected, so reactivating it
// restores both as they were (ADR 0013). Deactivating a Deactivated Customer
// keeps the time it was first deactivated.
func (s *Service) DeactivateCustomer(ctx context.Context, caller tenancy.User, id tenancy.CustomerID) (StoredCustomer, error) {
	return s.changeCustomer(ctx, caller, func(tx *postgres.Tx) (StoredCustomer, error) {
		return tx.DeactivateCustomer(ctx, id)
	})
}

func (s *Service) ReactivateCustomer(ctx context.Context, caller tenancy.User, id tenancy.CustomerID) (StoredCustomer, error) {
	return s.changeCustomer(ctx, caller, func(tx *postgres.Tx) (StoredCustomer, error) {
		return tx.ReactivateCustomer(ctx, id)
	})
}

func (s *Service) changeCustomer(ctx context.Context, caller tenancy.User, change func(*postgres.Tx) (StoredCustomer, error)) (StoredCustomer, error) {
	if err := caller.ManageCustomers(); err != nil {
		return StoredCustomer{}, err
	}
	var stored StoredCustomer
	err := s.db.InTx(ctx, func(tx *postgres.Tx) (err error) {
		stored, err = change(tx)
		return err
	})
	return stored, err
}
