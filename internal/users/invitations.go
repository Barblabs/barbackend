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
	cognitoTimeout  = 30 * time.Second
	invitationClaim = 4 * cognitoTimeout
	firstRetryDelay = 30 * time.Second
	maxRetryDelay   = time.Hour
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
		var (
			invitation postgres.Invitation
			due        bool
		)
		err := s.db.InTx(ctx, func(tx *postgres.Tx) (err error) {
			invitation, due, err = tx.ClaimInvitation(ctx, now, now.Add(invitationClaim))
			return err
		})
		if err != nil || !due {
			return errors.Join(append(errs, err)...)
		}
		if _, err := s.send(ctx, invitation, now); err != nil {
			errs = append(errs, err)
		}
	}
}

func (s *Service) send(ctx context.Context, invitation postgres.Invitation, now time.Time) (string, error) {
	callCtx, cancel := context.WithTimeout(ctx, cognitoTimeout)
	defer cancel()
	sub, err := s.admin.CreateUser(callCtx, invitation.Email)
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
