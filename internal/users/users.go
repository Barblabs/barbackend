// Package users holds the use cases on Users: authenticating a request and
// creating, listing, changing the role of and disabling Users (ADR 0013),
// and on the Customers they belong to, since a Customer is created together
// with its first Customer Admin (ADR 0008).
package users

import (
	"context"
	"errors"
	"fmt"

	"barbackend/internal/cognito"
	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

var (
	// ErrUnauthenticated is an access token that identifies no User. It wraps
	// the cause, which is for logs only.
	ErrUnauthenticated = errors.New("unauthenticated")
	// ErrEmailTaken is an email that already signs in, in Cognito or in
	// Postgres: the two disagree when a Cognito user is deleted by hand.
	ErrEmailTaken   = errors.New("a user with this email already exists")
	ErrUserNotFound = postgres.ErrUserNotFound
)

type StoredUser = postgres.StoredUser

// Admin creates, disables and deletes users in the user pool.
// *cognito.Admin is the real one.
type Admin interface {
	CreateUser(ctx context.Context, email string) (sub string, err error)
	DisableUser(ctx context.Context, sub string) error
	DeleteUser(ctx context.Context, sub string) error
}

type Service struct {
	db       *postgres.DB
	verifier *cognito.Verifier
	admin    Admin
}

func New(db *postgres.DB, verifier *cognito.Verifier, admin Admin) *Service {
	return &Service{db: db, verifier: verifier, admin: admin}
}

// Authenticate resolves a Cognito access token to the User it signs in. A
// token that identifies no User fails with ErrUnauthenticated; a User who
// cannot sign in fails as tenancy.User.SignIn does.
func (s *Service) Authenticate(ctx context.Context, accessToken string) (tenancy.User, error) {
	u, err := s.identify(ctx, accessToken)
	if err != nil {
		return tenancy.User{}, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	if err := u.SignIn(); err != nil {
		return tenancy.User{}, err
	}
	return u, nil
}

func (s *Service) identify(ctx context.Context, accessToken string) (tenancy.User, error) {
	sub, err := s.verifier.Verify(ctx, accessToken)
	if err != nil {
		return tenancy.User{}, err
	}
	var u tenancy.User
	err = s.db.InTx(ctx, func(tx *postgres.Tx) (err error) {
		u, err = tx.UserBySub(ctx, sub)
		return err
	})
	return u, err
}

// Profile is the caller as the dashboard shows them.
type Profile struct {
	User tenancy.User
	// Customer is the zero Customer for a Platform Admin, who belongs to none.
	Customer tenancy.Customer
}

func (s *Service) Profile(ctx context.Context, caller tenancy.User) (Profile, error) {
	id, err := caller.ActsFor()
	if errors.Is(err, tenancy.ErrNoCustomer) {
		return Profile{User: caller}, nil
	}
	if err != nil {
		return Profile{}, err
	}
	var stored StoredCustomer
	err = s.db.InTx(ctx, func(tx *postgres.Tx) (err error) {
		stored, err = tx.Customer(ctx, id)
		return err
	})
	if err != nil {
		return Profile{}, err
	}
	return Profile{User: caller, Customer: stored.Customer}, nil
}

// Create invites a User through Cognito and stores them. It does not check
// who asks: callers that act for a User must check their role and Customer
// first.
func (s *Service) Create(ctx context.Context, email string, role tenancy.Role, customer tenancy.CustomerID) (StoredUser, error) {
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), email, role, customer)
	if err != nil {
		return StoredUser{}, err
	}
	return s.invite(ctx, u, nil)
}

// invite stores u in one transaction with whatever before stores, and has
// Cognito send their invitation. before runs first, so a row it cannot store,
// such as a Customer with a taken name, sends no invitation. When storing
// fails after Cognito created the user, the Cognito user is deleted again, so
// the email stays free.
func (s *Service) invite(ctx context.Context, u tenancy.User, before func(*postgres.Tx) error) (StoredUser, error) {
	var (
		sub    string
		stored StoredUser
	)
	err := s.db.InTx(ctx, func(tx *postgres.Tx) error {
		if before != nil {
			if err := before(tx); err != nil {
				return err
			}
		}
		var err error
		if sub, err = s.admin.CreateUser(ctx, u.Email()); err != nil {
			return err
		}
		stored, err = tx.CreateUser(ctx, u, sub)
		return err
	})
	if errors.Is(err, cognito.ErrUsernameExists) || errors.Is(err, postgres.ErrEmailTaken) {
		err = fmt.Errorf("%w: %w", ErrEmailTaken, err)
	}
	if err != nil && sub != "" {
		if delErr := s.admin.DeleteUser(context.WithoutCancel(ctx), sub); delErr != nil {
			err = errors.Join(err, delErr)
		}
	}
	if err != nil {
		return StoredUser{}, err
	}
	return stored, nil
}
