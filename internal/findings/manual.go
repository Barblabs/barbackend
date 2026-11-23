package findings

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"barbackend/internal/finding"
	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
)

// MaxCloseNoteLength is, in characters, the longest note a User can give to
// close a Finding.
const MaxCloseNoteLength = 2000

var (
	// ErrInvalidClose is a close by hand with a reason a User cannot give, no
	// note, or a reopen time missing, not allowed, or not ahead.
	ErrInvalidClose = errors.New("invalid close")
	// ErrFindingNotFound is a Finding the caller's Customer does not have.
	ErrFindingNotFound = errors.New("finding not found")
	// ErrFindingClosed is a close of a Finding that is already closed.
	ErrFindingClosed = errors.New("finding is already closed")
	// ErrNotClosedByHand is a reopen of a Finding that is open or that closed
	// on its own, which only a match reopens.
	ErrNotClosedByHand = errors.New("finding is not closed by hand")
)

// ClosedByHand is a Finding that a User closed, with its Asset and the close.
type ClosedByHand = postgres.FindingClosedByHand

// CloseByHand closes an open Finding of the caller's Customer for reason,
// which must be one a User gives, with why in note and, for an accepted risk
// or a postponed one, when a match may reopen it (ADR 0035). The caller may be
// a Customer Admin or a Viewer. It fails with ErrInvalidClose,
// ErrFindingNotFound or ErrFindingClosed.
func (s *Service) CloseByHand(ctx context.Context, caller tenancy.User, id finding.ID, reason finding.CloseReason, note string, reopenAt *time.Time) error {
	customer, err := caller.ActsFor()
	if err != nil {
		return err
	}
	note = strings.TrimSpace(note)
	if err := s.checkClose(reason, note, reopenAt); err != nil {
		return err
	}
	err = s.db.InTx(ctx, func(tx *postgres.Tx) error {
		state, err := tx.FindingCloseOfCustomer(ctx, customer, id)
		if errors.Is(err, postgres.ErrNotFound) {
			return ErrFindingNotFound
		}
		if err != nil {
			return err
		}
		if state.Closed {
			return ErrFindingClosed
		}
		closed, err := tx.CloseFindingByHand(ctx, customer, id, postgres.ManualClose{Reason: reason, By: caller.ID(), Note: note, ReopenAt: reopenAt})
		if err == nil && !closed {
			return ErrFindingClosed
		}
		return err
	})
	if err != nil {
		return err
	}
	s.changed()
	return nil
}

func (s *Service) checkClose(reason finding.CloseReason, note string, reopenAt *time.Time) error {
	switch {
	case !reason.ByHand():
		return fmt.Errorf("%w: %s is not a reason a User gives", ErrInvalidClose, reason)
	case note == "":
		return fmt.Errorf("%w: a note is required", ErrInvalidClose)
	case utf8.RuneCountInString(note) > MaxCloseNoteLength:
		return fmt.Errorf("%w: the note is longer than %d characters", ErrInvalidClose, MaxCloseNoteLength)
	case reason.Expires() && reopenAt == nil:
		return fmt.Errorf("%w: %s needs a reopen time", ErrInvalidClose, reason)
	case !reason.Expires() && reopenAt != nil:
		return fmt.Errorf("%w: %s takes no reopen time", ErrInvalidClose, reason)
	case reopenAt != nil && !reopenAt.After(s.now()):
		return fmt.Errorf("%w: the reopen time must be ahead", ErrInvalidClose)
	}
	return nil
}

// ReopenByHand reopens a Finding of the caller's Customer that a User closed,
// whatever the reason (ADR 0035). It fails with ErrFindingNotFound or
// ErrNotClosedByHand.
func (s *Service) ReopenByHand(ctx context.Context, caller tenancy.User, id finding.ID) error {
	customer, err := caller.ActsFor()
	if err != nil {
		return err
	}
	err = s.db.InTx(ctx, func(tx *postgres.Tx) error {
		state, err := tx.FindingCloseOfCustomer(ctx, customer, id)
		if errors.Is(err, postgres.ErrNotFound) {
			return ErrFindingNotFound
		}
		if err != nil {
			return err
		}
		if !state.Closed || !state.Reason.ByHand() {
			return ErrNotClosedByHand
		}
		reopened, err := tx.ReopenFindingByHand(ctx, customer, id)
		if err == nil && !reopened {
			return ErrNotClosedByHand
		}
		return err
	})
	if err != nil {
		return err
	}
	s.changed()
	return nil
}

// ClosedByHand is the Findings of the caller's Customer that a User closed,
// newest close first, so one can be reopened.
func (s *Service) ClosedByHand(ctx context.Context, caller tenancy.User) ([]ClosedByHand, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return nil, err
	}
	return postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]ClosedByHand, error) {
		return tx.FindingsOfCustomerClosedByHand(ctx, customer)
	})
}
