package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"barbackend/internal/postgres/sqlcgen"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

const userEmailKey = "users_email_key"

var (
	// ErrEmailTaken is an email another User has.
	ErrEmailTaken = errors.New("another user has this email")
	// ErrUserNotFound is a User the Customer does not have.
	ErrUserNotFound = errors.New("user not found")
)

// StoredUser is a User of a Customer with what only the database records
// about them.
type StoredUser struct {
	User    tenancy.User
	Created time.Time
	// Disabled is when the User was disabled, zero while they are not.
	Disabled time.Time
}

// CreateUser stores a User with the Cognito sub that signs them in.
func (t *Tx) CreateUser(ctx context.Context, u tenancy.User, sub string) (StoredUser, error) {
	var customer pgtype.UUID
	if id, err := u.ActsFor(); err == nil {
		customer = customerUUID(id)
	}
	created, err := t.q.InsertUser(ctx, sqlcgen.InsertUserParams{
		ID:         uuid.UUID(u.ID()),
		CognitoSub: sub,
		Email:      u.Email(),
		CustomerID: customer,
		RoleID:     int16(u.Role()),
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation && pgErr.ConstraintName == userEmailKey {
		return StoredUser{}, fmt.Errorf("insert user %s: %w", u.ID(), ErrEmailTaken)
	}
	if err != nil {
		return StoredUser{}, fmt.Errorf("insert user %s: %w", u.ID(), err)
	}
	return StoredUser{User: u, Created: created}, nil
}

// UserBySub fails with ErrNotFound when no User has the Cognito sub.
func (t *Tx) UserBySub(ctx context.Context, sub string) (tenancy.User, error) {
	row, err := t.q.GetUserBySub(ctx, sub)
	if errors.Is(err, pgx.ErrNoRows) {
		return tenancy.User{}, fmt.Errorf("user with sub %q: %w", sub, ErrNotFound)
	}
	if err != nil {
		return tenancy.User{}, fmt.Errorf("get user with sub %q: %w", sub, err)
	}
	var customer tenancy.CustomerID
	if row.CustomerID.Valid {
		customer = tenancy.CustomerID(row.CustomerID.Bytes)
	}
	u, err := tenancy.RestoreUser(tenancy.UserID(row.ID), row.Email, tenancy.Role(row.RoleID), customer, tenancy.UserState{
		Disabled:            row.Disabled,
		CustomerDeactivated: row.CustomerDeactivated,
	})
	if err != nil {
		return tenancy.User{}, fmt.Errorf("restore user %s: %w", row.ID, err)
	}
	return u, nil
}

// Users are the Users of the Customer, disabled ones included, ordered by
// email.
func (t *Tx) Users(ctx context.Context, customer tenancy.CustomerID) ([]StoredUser, error) {
	rows, err := t.q.ListCustomerUsers(ctx, customerUUID(customer))
	if err != nil {
		return nil, fmt.Errorf("list users of customer %s: %w", customer, err)
	}
	users := make([]StoredUser, 0, len(rows))
	for _, row := range rows {
		u, err := restoreStoredUser(row)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

// LockedUser is a User of a Customer whose Customer Admins cannot change
// until the transaction that locked it ends.
type LockedUser struct {
	User StoredUser
	// Sub is the Cognito sub that signs the User in.
	Sub string
	// ActiveAdmins is the number of active Customer Admins of the Customer.
	ActiveAdmins int
}

// LockUser locks the Customer until the transaction ends and returns its
// User with the id, so two changes to the Customer's Customer Admins run one after
// the other. A User of another Customer is ErrUserNotFound.
//
// The Customer Admins are counted in a statement after the lock: under read
// committed, a count in the locking statement would use the snapshot taken
// before it waited for the lock, missing the change it waited for.
func (t *Tx) LockUser(ctx context.Context, customer tenancy.CustomerID, id tenancy.UserID) (LockedUser, error) {
	if err := t.q.LockCustomer(ctx, uuid.UUID(customer)); err != nil {
		return LockedUser{}, fmt.Errorf("lock customer %s: %w", customer, err)
	}
	row, err := t.q.GetCustomerUser(ctx, sqlcgen.GetCustomerUserParams{CustomerID: customerUUID(customer), ID: uuid.UUID(id)})
	if errors.Is(err, pgx.ErrNoRows) {
		return LockedUser{}, fmt.Errorf("user %s of customer %s: %w", id, customer, ErrUserNotFound)
	}
	if err != nil {
		return LockedUser{}, fmt.Errorf("get user %s: %w", id, err)
	}
	stored, err := restoreStoredUser(row)
	if err != nil {
		return LockedUser{}, err
	}
	admins, err := t.q.CountActiveUsersWithRole(ctx, sqlcgen.CountActiveUsersWithRoleParams{
		CustomerID: customerUUID(customer),
		RoleID:     int16(tenancy.CustomerAdmin),
	})
	if err != nil {
		return LockedUser{}, fmt.Errorf("count customer admins of %s: %w", customer, err)
	}
	return LockedUser{User: stored, Sub: row.CognitoSub, ActiveAdmins: int(admins)}, nil
}

// SetUserRole stores the role of u on the User with its id.
func (t *Tx) SetUserRole(ctx context.Context, u tenancy.User) (StoredUser, error) {
	row, err := t.q.SetUserRole(ctx, sqlcgen.SetUserRoleParams{ID: uuid.UUID(u.ID()), RoleID: int16(u.Role())})
	if err != nil {
		return StoredUser{}, fmt.Errorf("set role of user %s: %w", u.ID(), err)
	}
	return restoreStoredUser(row)
}

// DisableUser keeps the time of the first disabling when the User is already
// disabled.
func (t *Tx) DisableUser(ctx context.Context, id tenancy.UserID) (StoredUser, error) {
	row, err := t.q.DisableUser(ctx, uuid.UUID(id))
	if err != nil {
		return StoredUser{}, fmt.Errorf("disable user %s: %w", id, err)
	}
	return restoreStoredUser(row)
}

func customerUUID(id tenancy.CustomerID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func restoreStoredUser(row sqlcgen.User) (StoredUser, error) {
	var customer tenancy.CustomerID
	if row.CustomerID.Valid {
		customer = tenancy.CustomerID(row.CustomerID.Bytes)
	}
	u, err := tenancy.RestoreUser(tenancy.UserID(row.ID), row.Email, tenancy.Role(row.RoleID), customer, tenancy.UserState{Disabled: row.DisabledAt != nil})
	if err != nil {
		return StoredUser{}, fmt.Errorf("restore user %s: %w", row.ID, err)
	}
	stored := StoredUser{User: u, Created: row.CreatedAt}
	if row.DisabledAt != nil {
		stored.Disabled = *row.DisabledAt
	}
	return stored, nil
}
