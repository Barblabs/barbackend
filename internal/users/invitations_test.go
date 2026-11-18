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

// clock is a time that only moves when a test moves it.
type clock struct{ now time.Time }

func newClock(svc *users.Service) *clock {
	c := &clock{now: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)}
	users.SetClock(svc, func() time.Time { return c.now })
	return c
}

func TestAnInvitationCognitoFailsIsSentByALaterPass(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{}
	svc, db := newService(t, admin)
	clock := newClock(svc)
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
	if !invited.User.Pending() || !slices.ContainsFunc(listed, func(u users.StoredUser) bool { return u.User.ID() == invited.User.ID() && u.User.Pending() }) {
		t.Errorf("invited = %+v, listed = %+v, want the User pending in both", invited, listed)
	}
	if _, err := svc.ByEmail(context.Background(), "viewer@example.com"); !errors.Is(err, tenancy.ErrUserPending) {
		t.Errorf("signing in pending: err = %v, want ErrUserPending", err)
	}

	admin.err = nil
	clock.now = clock.now.Add(time.Hour)
	if err := svc.SendDueInvitations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(admin.created) != 2 || userBySub(t, db, admin.created[1]).SignIn() != nil {
		t.Errorf("invited %d, want the viewer invited and able to sign in", len(admin.created))
	}
}

func TestAnInterruptedInviteIsSentOnceItsClaimEnds(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{}
	svc, db := newService(t, admin)
	clock := newClock(svc)
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "admin@example.com", tenancy.PlatformAdmin, tenancy.CustomerID{})
	if err != nil {
		t.Fatal(err)
	}
	claimedUntil := clock.now.Add(time.Minute)
	if err := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, _, err := tx.CreatePendingUser(context.Background(), u, claimedUntil)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	clock.now = claimedUntil.Add(-time.Second)
	if err := svc.SendDueInvitations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(admin.created) != 0 {
		t.Fatalf("invited %d while claimed, want none", len(admin.created))
	}
	clock.now = claimedUntil
	if err := svc.SendDueInvitations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(admin.created) != 1 || userBySub(t, db, admin.created[0]).ID() != u.ID() {
		t.Errorf("invited %v, want the platform admin under its sub", admin.created)
	}
}

func TestDisablingAPendingUserCancelsTheirInvitation(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{}
	svc, db := newService(t, admin)
	clock := newClock(svc)
	caller := customerAdmin(t, svc, db, admin)
	admin.err = errors.New("cognito unreachable")
	invited, err := svc.InviteUser(context.Background(), caller, "viewer@example.com", tenancy.Viewer)
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := svc.DisableUser(context.Background(), caller, invited.User.ID())
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Disabled.IsZero() || !disabled.User.Pending() {
		t.Errorf("disabled = %+v, want the User disabled and still pending", disabled)
	}

	admin.err = nil
	clock.now = clock.now.Add(time.Hour)
	if err := svc.SendDueInvitations(context.Background()); err != nil {
		t.Fatal(err)
	}

	if len(admin.created) != 1 {
		t.Errorf("invited %d, want only the Customer Admin", len(admin.created))
	}
}

func TestAFailingInvitationWaitsTwiceAsLongEachTimeUpToAnHour(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{err: errors.New("cognito unreachable")}
	svc, _ := newService(t, admin)
	clock := newClock(svc)
	if _, err := svc.Create(context.Background(), "admin@example.com", tenancy.PlatformAdmin, tenancy.CustomerID{}); err != nil {
		t.Fatal(err)
	}

	start := clock.now
	for _, delay := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour} {
		calls := admin.calls
		clock.now = start.Add(delay - time.Second)
		_ = svc.SendDueInvitations(context.Background())
		if admin.calls != calls {
			t.Fatalf("retried %s after the last failure, want %s", delay-time.Second, delay)
		}
		start = start.Add(delay)
		clock.now = start
		_ = svc.SendDueInvitations(context.Background())
		if admin.calls != calls+1 {
			t.Fatalf("not retried %s after the last failure", delay)
		}
	}
}
