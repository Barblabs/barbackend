package users

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"barbackend/internal/postgres"
)

const (
	// invitationClaim outlasts a Cognito call, so no two callers send the
	// same Invitation at once.
	invitationClaim    = 2 * time.Minute
	invitationsPerPass = 20
	firstRetryDelay    = 30 * time.Second
	maxRetryDelay      = time.Hour
)

// SendInvitations sends the Invitations that are due every interval, until
// ctx ends, and logs those that fail.
func (s *Service) SendInvitations(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := s.SendDueInvitations(ctx, time.Now()); err != nil {
			log.Printf("users: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// SendDueInvitations has Cognito send every Invitation due at now, and stores
// the sub of each User it invites. A failed Invitation is due again after a
// delay that doubles with each attempt, up to an hour. Invitations of
// disabled Users and of Deactivated Customers wait.
func (s *Service) SendDueInvitations(ctx context.Context, now time.Time) error {
	var errs []error
	for {
		claimed, err := postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]postgres.Invitation, error) {
			return tx.ClaimInvitations(ctx, now, now.Add(invitationClaim), invitationsPerPass)
		})
		if err != nil {
			return errors.Join(append(errs, err)...)
		}
		for _, invitation := range claimed {
			if _, err := s.send(ctx, invitation, now); err != nil {
				errs = append(errs, err)
			}
		}
		if len(claimed) < invitationsPerPass {
			return errors.Join(errs...)
		}
	}
}

// send runs no transaction while Cognito is called, so a slow Cognito holds
// no lock.
func (s *Service) send(ctx context.Context, invitation postgres.Invitation, now time.Time) (string, error) {
	sub, err := s.admin.CreateUser(ctx, invitation.Email)
	if err != nil {
		err = fmt.Errorf("invite user %s, attempt %d: %w", invitation.User, invitation.Attempt, err)
		retryErr := s.db.InTx(ctx, func(tx *postgres.Tx) error {
			return tx.RetryInvitation(ctx, invitation.User, now.Add(retryDelay(invitation.Attempt)), err)
		})
		return "", errors.Join(err, retryErr)
	}
	if err := s.db.InTx(ctx, func(tx *postgres.Tx) error { return tx.CompleteInvitation(ctx, invitation.User, sub) }); err != nil {
		return "", err
	}
	return sub, nil
}

func retryDelay(attempt int) time.Duration {
	delay := firstRetryDelay
	for range attempt - 1 {
		delay *= 2
		if delay >= maxRetryDelay {
			return maxRetryDelay
		}
	}
	return delay
}
