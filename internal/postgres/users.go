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

// StoredUser is a User with what only the database records about them.
type StoredUser struct {
	User tenancy.User
	// Sub is the Cognito sub that signs the User in, empty while they are
	// pending.
	Sub     string
	Created time.Time
	// Disabled is when the User was disabled, zero while they are not.
	Disabled time.Time
}

// CreateUser stores a User with the Cognito sub that signs them in.
func (t *Tx) CreateUser(ctx context.Context, u tenancy.User, sub string) (StoredUser, error) {
	created, err := t.insertUser(ctx, u, &sub)
	if err != nil {
		return StoredUser{}, err
	}
	return StoredUser{User: u, Sub: sub, Created: created}, nil
}

// CreatePendingUser stores a User who cannot sign in until their Invitation
// is sent, with the Invitation claimed by the caller until claimedUntil.
func (t *Tx) CreatePendingUser(ctx context.Context, u tenancy.User, claimedUntil time.Time) (StoredUser, Invitation, error) {
	created, err := t.insertUser(ctx, u, nil)
	if err != nil {
		return StoredUser{}, Invitation{}, err
	}
	attempts, err := t.q.InsertUserInvitation(ctx, sqlcgen.InsertUserInvitationParams{UserID: uuid.UUID(u.ID()), NextAttemptAt: claimedUntil})
	if err != nil {
		return StoredUser{}, Invitation{}, fmt.Errorf("insert invitation of user %s: %w", u.ID(), err)
	}
	customer, _ := u.Customer()
	pending, err := tenancy.RestoreUser(u.ID(), u.Email(), u.Role(), customer, tenancy.UserState{Pending: true})
	if err != nil {
		return StoredUser{}, Invitation{}, err
	}
	return StoredUser{User: pending, Created: created}, Invitation{User: u.ID(), Email: u.Email(), Attempt: int(attempts)}, nil
}

func (t *Tx) insertUser(ctx context.Context, u tenancy.User, sub *string) (time.Time, error) {
	var customer pgtype.UUID
	if id, ok := u.Customer(); ok {
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
		return time.Time{}, fmt.Errorf("insert user %s: %w", u.ID(), tenancy.ErrEmailTaken)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("insert user %s: %w", u.ID(), err)
	}
	return created, nil
}

// Invitation is one attempt, claimed by its caller, to have Cognito invite a
// pending User.
type Invitation struct {
	User  tenancy.UserID
	Email string
	// Attempt counts from 1.
	Attempt int
}

// ClaimInvitation claims, until claimedUntil, the Invitation that has been
// due the longest at now, and reports false when none is. It skips the
// Invitations of disabled Users and of Deactivated Customers, and one another
// transaction is claiming.
func (t *Tx) ClaimInvitation(ctx context.Context, now, claimedUntil time.Time) (Invitation, bool, error) {
	row, err := t.q.ClaimDueUserInvitation(ctx, sqlcgen.ClaimDueUserInvitationParams{Now: now, ClaimedUntil: claimedUntil})
	if errors.Is(err, pgx.ErrNoRows) {
		return Invitation{}, false, nil
	}
	if err != nil {
		return Invitation{}, false, fmt.Errorf("claim invitation: %w", err)
	}
	return Invitation{User: tenancy.UserID(row.UserID), Email: row.Email, Attempt: int(row.Attempts)}, true, nil
}

// CompleteInvitation stores the Cognito sub that signs the User in and drops
// their Invitation. It fails with ErrNotFound when the User has a sub
// already.
func (t *Tx) CompleteInvitation(ctx context.Context, id tenancy.UserID, sub string) error {
	n, err := t.q.SetUserSub(ctx, sqlcgen.SetUserSubParams{ID: uuid.UUID(id), CognitoSub: &sub})
	if err != nil {
		return fmt.Errorf("set sub of user %s: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("pending user %s: %w", id, ErrNotFound)
	}
	if err := t.q.DeleteUserInvitation(ctx, uuid.UUID(id)); err != nil {
		return fmt.Errorf("delete invitation of user %s: %w", id, err)
	}
	return nil
}

// RetryInvitation makes the User's Invitation due again at next, recording
// why the last attempt failed. It fails with ErrNotFound when the User has
// no Invitation.
func (t *Tx) RetryInvitation(ctx context.Context, id tenancy.UserID, next time.Time, cause error) error {
	msg := cause.Error()
	n, err := t.q.RetryUserInvitation(ctx, sqlcgen.RetryUserInvitationParams{UserID: uuid.UUID(id), NextAttemptAt: next, LastError: &msg})
	if err != nil {
		return fmt.Errorf("retry invitation of user %s: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("invitation of user %s: %w", id, ErrNotFound)
	}
	return nil
}

// UserBySub fails with ErrNotFound when no User has the Cognito sub.
func (t *Tx) UserBySub(ctx context.Context, sub string) (tenancy.User, error) {
	row, err := t.q.GetUserBySub(ctx, &sub)
	if errors.Is(err, pgx.ErrNoRows) {
		return tenancy.User{}, fmt.Errorf("user with sub %q: %w", sub, ErrNotFound)
	}
	if err != nil {
		return tenancy.User{}, fmt.Errorf("get user with sub %q: %w", sub, err)
	}
	stored, err := restoreUser(row.User, row.CustomerDeactivated)
	return stored.User, err
}

// UserByEmail fails with ErrNotFound when no User has the email.
func (t *Tx) UserByEmail(ctx context.Context, email string) (tenancy.User, error) {
	row, err := t.q.GetUserByEmail(ctx, email)
	if errors.Is(err, pgx.ErrNoRows) {
		return tenancy.User{}, fmt.Errorf("user with email %q: %w", email, ErrNotFound)
	}
	if err != nil {
		return tenancy.User{}, fmt.Errorf("get user with email %q: %w", email, err)
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
		return StoredUser{}, fmt.Errorf("user %s of customer %s: %w", id, customer, tenancy.ErrUserNotFound)
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

// ActiveCustomerAdmins counts the Customer Admins who can sign in: neither
// disabled nor pending.
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
		return StoredUser{}, fmt.Errorf("user %s of customer %s: %w", id, customer, tenancy.ErrUserNotFound)
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
		Pending:             row.CognitoSub == nil,
		CustomerDeactivated: customerDeactivated,
	})
	if err != nil {
		return StoredUser{}, fmt.Errorf("restore user %s: %w", row.ID, err)
	}
	stored := StoredUser{User: u, Sub: valueOrZero(row.CognitoSub), Created: row.CreatedAt}
	if row.DisabledAt != nil {
		stored.Disabled = *row.DisabledAt
	}
	return stored, nil
}
