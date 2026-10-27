package users

import (
	"context"
	"fmt"

	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

type StoredUser = postgres.StoredUser

var ErrUserNotFound = postgres.ErrUserNotFound

// Users are the Users of the caller's Customer, disabled ones included.
func (s *Service) Users(ctx context.Context, caller tenancy.User) ([]StoredUser, error) {
	customer, err := caller.ManageUsers()
	if err != nil {
		return nil, err
	}
	var users []StoredUser
	err = s.db.InTx(ctx, func(tx *postgres.Tx) (err error) {
		users, err = tx.Users(ctx, customer)
		return err
	})
	return users, err
}

// InviteUser creates a Viewer or Customer Admin of the caller's Customer,
// who is invited by email.
func (s *Service) InviteUser(ctx context.Context, caller tenancy.User, email string, role tenancy.Role) (StoredUser, error) {
	customer, err := caller.ManageUsers()
	if err != nil {
		return StoredUser{}, err
	}
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), email, role, customer)
	if err != nil {
		return StoredUser{}, err
	}
	return s.invite(ctx, u, nil)
}

// ChangeRole makes a User of the caller's Customer a Viewer or a Customer
// Admin. Demoting the last active Customer Admin fails with
// tenancy.ErrLastCustomerAdmin.
func (s *Service) ChangeRole(ctx context.Context, caller tenancy.User, id tenancy.UserID, role tenancy.Role) (StoredUser, error) {
	return s.changeUser(ctx, caller, id, func(tx *postgres.Tx, locked postgres.LockedUser) (StoredUser, error) {
		changed, err := locked.User.User.WithRole(role, locked.ActiveAdmins)
		if err != nil {
			return StoredUser{}, err
		}
		return tx.SetUserRole(ctx, changed)
	})
}

// DisableUser disables a User of the caller's Customer in Postgres and in
// Cognito; they are never deleted. Disabling the last active Customer Admin
// fails with tenancy.ErrLastCustomerAdmin. When Cognito fails nothing is
// stored, and when storing fails after Cognito the User stays disabled in
// Cognito only, unable to sign in until a retry disables them in both.
func (s *Service) DisableUser(ctx context.Context, caller tenancy.User, id tenancy.UserID) (StoredUser, error) {
	return s.changeUser(ctx, caller, id, func(tx *postgres.Tx, locked postgres.LockedUser) (StoredUser, error) {
		disabled, err := locked.User.User.Disable(locked.ActiveAdmins)
		if err != nil {
			return StoredUser{}, err
		}
		stored, err := tx.DisableUser(ctx, disabled.ID())
		if err != nil {
			return StoredUser{}, err
		}
		if err := s.admin.DisableUser(ctx, locked.Sub); err != nil {
			return StoredUser{}, fmt.Errorf("disable user %s: %w", id, err)
		}
		return stored, nil
	})
}

func (s *Service) changeUser(ctx context.Context, caller tenancy.User, id tenancy.UserID, change func(*postgres.Tx, postgres.LockedUser) (StoredUser, error)) (StoredUser, error) {
	customer, err := caller.ManageUsers()
	if err != nil {
		return StoredUser{}, err
	}
	var stored StoredUser
	err = s.db.InTx(ctx, func(tx *postgres.Tx) error {
		locked, err := tx.LockUser(ctx, customer, id)
		if err != nil {
			return err
		}
		stored, err = change(tx, locked)
		return err
	})
	return stored, err
}
