package postgres

import (
	"context"
	"errors"
	"fmt"

	"barbackend/internal/postgres/sqlcgen"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

const userEmailKey = "users_email_key"

// ErrEmailTaken is an email another User has.
var ErrEmailTaken = errors.New("another user has this email")

// CreateUser stores a User with the Cognito sub that signs them in.
func (t *Tx) CreateUser(ctx context.Context, u tenancy.User, sub string) error {
	var customer pgtype.UUID
	if id, err := u.ActsFor(); err == nil {
		customer = pgtype.UUID{Bytes: id, Valid: true}
	}
	err := t.q.InsertUser(ctx, sqlcgen.InsertUserParams{
		ID:         uuid.UUID(u.ID()),
		CognitoSub: sub,
		Email:      u.Email(),
		CustomerID: customer,
		RoleID:     int16(u.Role()),
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation && pgErr.ConstraintName == userEmailKey {
		return fmt.Errorf("insert user %s: %w", u.ID(), ErrEmailTaken)
	}
	if err != nil {
		return fmt.Errorf("insert user %s: %w", u.ID(), err)
	}
	return nil
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
