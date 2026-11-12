package users_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"barbackend/internal/users"
	"github.com/google/uuid"
)

func TestAnInvitationCognitoFailsIsSentByALaterPass(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{}
	svc, db := newService(t, admin)
	caller := customerAdmin(t, svc, db, admin)
	admin.err = errors.New("cognito unreachable")

	invited, err := svc.InviteUser(context.Background(), caller, "viewer@example.com", tenancy.Viewer)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := svc.Users(context.Background(), caller)
	if err != nil {
		t.Fatal(err)
	}
	isInvited := func(u users.StoredUser) bool { return u.User.ID() == invited.User.ID() }
	if !invited.User.Pending() || !slices.ContainsFunc(listed, func(u users.StoredUser) bool { return isInvited(u) && u.User.Pending() }) {
		t.Errorf("invited = %+v, listed = %+v, want the User pending in both", invited, listed)
	}
	if _, err := svc.ByEmail(context.Background(), "viewer@example.com"); !errors.Is(err, tenancy.ErrUserPending) {
		t.Errorf("signing in pending: err = %v, want ErrUserPending", err)
	}

	admin.err = nil
	if err := svc.SendDueInvitations(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(admin.created) != 1 {
		t.Errorf("invited %d before the retry delay, want only the Customer Admin", len(admin.created))
	}
	if err := svc.SendDueInvitations(context.Background(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(admin.created) != 2 || userBySub(t, db, admin.created[1]).SignIn() != nil {
		t.Errorf("invited %d, want the viewer invited and able to sign in", len(admin.created))
	}
}

// Storing the pending User without sending is where a crash after the
// commit leaves an invite.
func TestAnInterruptedInviteIsSentOnceItsClaimEnds(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{}
	svc, db := newService(t, admin)
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "admin@example.com", tenancy.PlatformAdmin, tenancy.CustomerID{})
	if err != nil {
		t.Fatal(err)
	}
	claimedUntil := time.Now().Add(time.Minute)
	if err := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, _, err := tx.CreatePendingUser(context.Background(), u, claimedUntil)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if err := svc.SendDueInvitations(context.Background(), claimedUntil.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(admin.created) != 0 {
		t.Fatalf("invited %d while claimed, want none", len(admin.created))
	}
	if err := svc.SendDueInvitations(context.Background(), claimedUntil); err != nil {
		t.Fatal(err)
	}
	if len(admin.created) != 1 || userBySub(t, db, admin.created[0]).ID() != u.ID() {
		t.Errorf("invited %v, want the platform admin under its sub", admin.created)
	}
}

func TestADisabledPendingUserIsNotInvited(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{}
	svc, db := newService(t, admin)
	caller := customerAdmin(t, svc, db, admin)
	admin.err = errors.New("cognito unreachable")
	invited, err := svc.InviteUser(context.Background(), caller, "viewer@example.com", tenancy.Viewer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DisableUser(context.Background(), caller, invited.User.ID()); err != nil {
		t.Fatal(err)
	}

	admin.err = nil
	if err := svc.SendDueInvitations(context.Background(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if len(admin.created) != 1 {
		t.Errorf("invited %d, want only the Customer Admin", len(admin.created))
	}
}

func TestAFailingInvitationWaitsTwiceAsLongEachTimeUpToAnHour(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{err: errors.New("cognito unreachable")}
	svc, db := newService(t, admin)
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "admin@example.com", tenancy.PlatformAdmin, tenancy.CustomerID{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	if err := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, _, err := tx.CreatePendingUser(context.Background(), u, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.SendDueInvitations(context.Background(), now); err == nil {
		t.Fatal("first attempt succeeded, want Cognito's failure")
	}

	// The invite's own attempt is the first, so the worker's first failure is
	// the second.
	for _, delay := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour} {
		calls := admin.calls
		_ = svc.SendDueInvitations(context.Background(), now.Add(delay-time.Second))
		if admin.calls != calls {
			t.Fatalf("retried %s after the last failure, want %s", delay-time.Second, delay)
		}
		now = now.Add(delay)
		_ = svc.SendDueInvitations(context.Background(), now)
		if admin.calls != calls+1 {
			t.Fatalf("not retried %s after the last failure", delay)
		}
	}
}
