package users

import (
	"context"

	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
)

// Users are the Users of the caller's Customer, disabled ones included.
func (s *Service) Users(ctx context.Context, caller tenancy.User) ([]StoredUser, error) {
	customer, err := caller.ManageUsers()
	if err != nil {
		return nil, err
	}
	return postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]StoredUser, error) { return tx.Users(ctx, customer) })
}

// InviteUser creates a Viewer or Customer Admin of the caller's Customer,
// who is invited by email.
func (s *Service) InviteUser(ctx context.Context, caller tenancy.User, email string, role tenancy.Role) (StoredUser, error) {
	customer, err := caller.ManageUsers()
	if err != nil {
		return StoredUser{}, err
	}
	return s.Create(ctx, email, role, customer)
}

// ChangeRole makes a User of the caller's Customer a Viewer or a Customer
// Admin. Demoting the last active Customer Admin fails with
// tenancy.ErrLastCustomerAdmin.
func (s *Service) ChangeRole(ctx context.Context, caller tenancy.User, id tenancy.UserID, role tenancy.Role) (StoredUser, error) {
	var stored StoredUser
	err := s.changeUsers(ctx, caller, func(tx *postgres.Tx, customer tenancy.CustomerID) (err error) {
		if stored, err = tx.User(ctx, customer, id); err != nil {
			return err
		}
		if stored.User, err = stored.User.WithRole(role); err != nil {
			return err
		}
		if err := tx.SetUserRole(ctx, stored.User); err != nil {
			return err
		}
		return requireActiveCustomerAdmin(ctx, tx, customer)
	})
	if err != nil {
		return StoredUser{}, err
	}
	return stored, nil
}

// DisableUser disables a User of the caller's Customer; they are never
// deleted. Authenticate refuses them from the next request on, while Cognito
// still signs them in (ADR 0026). Disabling the last active Customer Admin
// fails with tenancy.ErrLastCustomerAdmin.
func (s *Service) DisableUser(ctx context.Context, caller tenancy.User, id tenancy.UserID) (StoredUser, error) {
	var stored StoredUser
	err := s.changeUsers(ctx, caller, func(tx *postgres.Tx, customer tenancy.CustomerID) (err error) {
		if stored, err = tx.DisableUser(ctx, customer, id); err != nil {
			return err
		}
		return requireActiveCustomerAdmin(ctx, tx, customer)
	})
	if err != nil {
		return StoredUser{}, err
	}
	return stored, nil
}

func (s *Service) changeUsers(ctx context.Context, caller tenancy.User, change func(*postgres.Tx, tenancy.CustomerID) error) error {
	customer, err := caller.ManageUsers()
	if err != nil {
		return err
	}
	return s.db.InTx(ctx, func(tx *postgres.Tx) error {
		if err := tx.LockCustomer(ctx, customer); err != nil {
			return err
		}
		return change(tx, customer)
	})
}

func requireActiveCustomerAdmin(ctx context.Context, tx *postgres.Tx, customer tenancy.CustomerID) error {
	admins, err := tx.ActiveCustomerAdmins(ctx, customer)
	if err != nil {
		return err
	}
	return tenancy.RequireActiveCustomerAdmin(admins)
}
