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

func claim(t *testing.T, db *postgres.DB, now time.Time) (postgres.Invitation, bool) {
	t.Helper()
	var (
		claimed postgres.Invitation
		due     bool
	)
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		claimed, due, err = tx.ClaimInvitation(context.Background(), now, now.Add(time.Minute))
		return err
	})
	return claimed, due
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

	_, early := claim(t, db, invitedAt.Add(-time.Second))
	got, due := claim(t, db, invitedAt)
	_, whileClaimed := claim(t, db, invitedAt.Add(time.Second))

	if early || whileClaimed {
		t.Errorf("claimed early = %t, while claimed = %t, want neither", early, whileClaimed)
	}
	want := postgres.Invitation{User: u.User.ID(), Email: u.User.Email(), Attempt: 2}
	if !due || got != want {
		t.Errorf("claimed when due = %+v, %t, want %+v", got, due, want)
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

	if claimed, due := claim(t, db, invitedAt); due {
		t.Errorf("claimed %+v, want none", claimed)
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
	if claimed, due := claim(t, db, invitedAt.Add(time.Hour)); due {
		t.Errorf("claimed after completing %+v, want none", claimed)
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

	if claimed, early := claim(t, db, next.Add(-time.Second)); early {
		t.Errorf("claimed %+v before the next attempt, want none", claimed)
	}
	if _, due := claim(t, db, next); !due {
		t.Error("nothing claimed at the next attempt, want the invitation")
	}
}

func TestAnInvitationBeingClaimedIsSkippedByAnotherClaim(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)
	createPending(t, db, newCustomer(t, db), invitedAt)
	firstClaimed := make(chan struct{})
	secondDue := make(chan bool, 1)
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
		select {
		case secondWasDue = <-secondDue:
		case <-time.After(5 * time.Second):
			t.Error("the second claim waited for the first")
		}
		return err
	})

	if err := <-secondErr; err != nil {
		t.Fatal(err)
	}
	if !firstDue || secondWasDue {
		t.Errorf("first claim found one = %t, second while the first is open found one = %t, want only the first", firstDue, secondWasDue)
	}
}
