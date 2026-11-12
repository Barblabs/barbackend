package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

var invitedAt = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

func createPending(t *testing.T, db *postgres.DB, customer tenancy.CustomerID, claimedUntil time.Time) postgres.StoredUser {
	t.Helper()
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), uuid.NewString()+"@example.com", tenancy.Viewer, customer)
	if err != nil {
		t.Fatal(err)
	}
	var stored postgres.StoredUser
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		stored, _, err = tx.CreatePendingUser(context.Background(), u, claimedUntil)
		return err
	})
	return stored
}

// claim returns the Invitation claimed at now, or nil when none is due.
func claim(t *testing.T, db *postgres.DB, now time.Time) []postgres.Invitation {
	t.Helper()
	var claimed []postgres.Invitation
	inTx(t, db, func(tx *postgres.Tx) error {
		invitation, due, err := tx.ClaimInvitation(context.Background(), now, now.Add(time.Minute))
		if due {
			claimed = append(claimed, invitation)
		}
		return err
	})
	return claimed
}

func TestAPendingUserIsListedButNotFoundBySub(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)
	customer := newCustomer(t, db)
	created := createPending(t, db, customer, invitedAt)

	var listed []postgres.StoredUser
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		listed, err = tx.Users(context.Background(), customer)
		return err
	})

	if len(listed) != 1 || listed[0].User != created.User || !listed[0].User.Pending() || listed[0].Sub != "" {
		t.Errorf("listed = %+v, want only %+v, pending and with no sub", listed, created)
	}
	if err := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.UserBySub(context.Background(), "")
		return err
	}); !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("user with no sub: err = %v, want ErrNotFound", err)
	}
}

func TestAnInvitationIsClaimedOnceItIsDue(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)
	u := createPending(t, db, newCustomer(t, db), invitedAt)

	early := claim(t, db, invitedAt.Add(-time.Second))
	due := claim(t, db, invitedAt)
	whileClaimed := claim(t, db, invitedAt.Add(time.Second))

	if len(early) != 0 || len(whileClaimed) != 0 {
		t.Errorf("claimed early = %v, while claimed = %v, want neither", early, whileClaimed)
	}
	want := postgres.Invitation{User: u.User.ID(), Email: u.User.Email(), Attempt: 2}
	if len(due) != 1 || due[0] != want {
		t.Errorf("claimed when due = %+v, want [%+v]", due, want)
	}
}

func TestInvitationsOfUsersWhoCannotSignInAreNotClaimed(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)
	disabled := createPending(t, db, newCustomer(t, db), invitedAt)
	customer, _ := disabled.User.Customer()
	inTx(t, db, func(tx *postgres.Tx) error {
		_, err := tx.DisableUser(context.Background(), customer, disabled.User.ID())
		return err
	})
	deactivated := newCustomer(t, db)
	createPending(t, db, deactivated, invitedAt)
	inTx(t, db, func(tx *postgres.Tx) error {
		_, err := tx.DeactivateCustomer(context.Background(), deactivated)
		return err
	})

	if claimed := claim(t, db, invitedAt); len(claimed) != 0 {
		t.Errorf("claimed = %+v, want none", claimed)
	}
}

func TestCompletingAnInvitationSignsTheUserIn(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)
	u := createPending(t, db, newCustomer(t, db), invitedAt)
	sub := uuid.NewString()

	inTx(t, db, func(tx *postgres.Tx) error { return tx.CompleteInvitation(context.Background(), u.User.ID(), sub) })

	var got tenancy.User
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		got, err = tx.UserBySub(context.Background(), sub)
		return err
	})
	if got.ID() != u.User.ID() || got.SignIn() != nil {
		t.Errorf("user with the sub = %+v, want %s able to sign in", got, u.User.ID())
	}
	if claimed := claim(t, db, invitedAt.Add(time.Hour)); len(claimed) != 0 {
		t.Errorf("claimed after completing = %+v, want none", claimed)
	}
	again := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		return tx.CompleteInvitation(context.Background(), u.User.ID(), uuid.NewString())
	})
	if !errors.Is(again, postgres.ErrNotFound) {
		t.Errorf("completing twice: err = %v, want ErrNotFound", again)
	}
}

func TestARetriedInvitationIsDueAtItsNextAttempt(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)
	u := createPending(t, db, newCustomer(t, db), invitedAt)
	next := invitedAt.Add(time.Hour)

	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.RetryInvitation(context.Background(), u.User.ID(), next, errors.New("cognito unreachable"))
	})

	if early := claim(t, db, next.Add(-time.Second)); len(early) != 0 {
		t.Errorf("claimed before the next attempt = %+v, want none", early)
	}
	if due := claim(t, db, next); len(due) != 1 {
		t.Errorf("claimed at the next attempt = %+v, want the invitation", due)
	}
}

func TestAnInvitationBeingClaimedIsSkippedByAnotherClaim(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)
	createPending(t, db, newCustomer(t, db), invitedAt)
	firstClaimed := make(chan struct{})
	secondDue := make(chan bool)
	secondErr := make(chan error, 1)
	go func() {
		<-firstClaimed
		var due bool
		secondErr <- db.InTx(context.Background(), func(tx *postgres.Tx) (err error) {
			_, due, err = tx.ClaimInvitation(context.Background(), invitedAt, invitedAt.Add(time.Minute))
			return err
		})
		secondDue <- due
	}()

	var firstDue, secondWasDue bool
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		_, firstDue, err = tx.ClaimInvitation(context.Background(), invitedAt, invitedAt.Add(time.Minute))
		close(firstClaimed)
		secondWasDue = <-secondDue
		return err
	})

	if err := <-secondErr; err != nil {
		t.Fatal(err)
	}
	if !firstDue || secondWasDue {
		t.Errorf("first claim found one = %t, second while the first is open found one = %t, want only the first", firstDue, secondWasDue)
	}
}
