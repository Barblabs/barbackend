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

// StoredUser is a User with what only the database records about them.
type StoredUser struct {
	User tenancy.User
	// Sub is the Cognito sub that signs the User in.
	Sub     string
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
	return StoredUser{User: u, Sub: sub, Created: created}, nil
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
	stored, err := restoreUser(row.User, row.CustomerDeactivated)
	return stored.User, err
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
		u, err := restoreUser(row.User, row.CustomerDeactivated)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

// User fails with ErrUserNotFound when the Customer has no User with the id.
func (t *Tx) User(ctx context.Context, customer tenancy.CustomerID, id tenancy.UserID) (StoredUser, error) {
	row, err := t.q.GetCustomerUser(ctx, sqlcgen.GetCustomerUserParams{CustomerID: customerUUID(customer), ID: uuid.UUID(id)})
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredUser{}, fmt.Errorf("user %s of customer %s: %w", id, customer, ErrUserNotFound)
	}
	if err != nil {
		return StoredUser{}, fmt.Errorf("get user %s: %w", id, err)
	}
	return restoreUser(row.User, row.CustomerDeactivated)
}

// LockCustomer locks the Customer until the transaction ends, so changes to
// its Users run one after the other. Under read committed, a statement reads
// the snapshot it took before waiting for a lock, so what must see the
// changes it waited for is read in later statements.
func (t *Tx) LockCustomer(ctx context.Context, customer tenancy.CustomerID) error {
	if err := t.q.LockCustomer(ctx, uuid.UUID(customer)); err != nil {
		return fmt.Errorf("lock customer %s: %w", customer, err)
	}
	return nil
}

func (t *Tx) ActiveCustomerAdmins(ctx context.Context, customer tenancy.CustomerID) (int, error) {
	n, err := t.q.CountActiveUsersWithRole(ctx, sqlcgen.CountActiveUsersWithRoleParams{
		CustomerID: customerUUID(customer),
		RoleID:     int16(tenancy.CustomerAdmin),
	})
	if err != nil {
		return 0, fmt.Errorf("count customer admins of %s: %w", customer, err)
	}
	return int(n), nil
}

// SetUserRole stores the role of u on the User with its id.
func (t *Tx) SetUserRole(ctx context.Context, u tenancy.User) error {
	if err := t.q.SetUserRole(ctx, sqlcgen.SetUserRoleParams{ID: uuid.UUID(u.ID()), RoleID: int16(u.Role())}); err != nil {
		return fmt.Errorf("set role of user %s: %w", u.ID(), err)
	}
	return nil
}

// DisableUser fails with ErrUserNotFound when the Customer has no User with
// the id, and keeps the time of the first disabling when the User is already
// disabled.
func (t *Tx) DisableUser(ctx context.Context, customer tenancy.CustomerID, id tenancy.UserID) (StoredUser, error) {
	n, err := t.q.DisableCustomerUser(ctx, sqlcgen.DisableCustomerUserParams{CustomerID: customerUUID(customer), ID: uuid.UUID(id)})
	if err != nil {
		return StoredUser{}, fmt.Errorf("disable user %s: %w", id, err)
	}
	if n == 0 {
		return StoredUser{}, fmt.Errorf("user %s of customer %s: %w", id, customer, ErrUserNotFound)
	}
	return t.User(ctx, customer, id)
}

func customerUUID(id tenancy.CustomerID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func restoreUser(row sqlcgen.User, customerDeactivated bool) (StoredUser, error) {
	var customer tenancy.CustomerID
	if row.CustomerID.Valid {
		customer = tenancy.CustomerID(row.CustomerID.Bytes)
	}
	u, err := tenancy.RestoreUser(tenancy.UserID(row.ID), row.Email, tenancy.Role(row.RoleID), customer, tenancy.UserState{
		Disabled:            row.DisabledAt != nil,
		CustomerDeactivated: customerDeactivated,
	})
	if err != nil {
		return StoredUser{}, fmt.Errorf("restore user %s: %w", row.ID, err)
	}
	stored := StoredUser{User: u, Sub: row.CognitoSub, Created: row.CreatedAt}
	if row.DisabledAt != nil {
		stored.Disabled = *row.DisabledAt
	}
	return stored, nil
}
