package users_test

import (
	"context"
	"errors"
	"testing"

	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/tenancy"
	"barbackend/internal/users"
	"github.com/google/uuid"
)

// fakeAdmin is a user pool that invites every email under a new sub, or
// fails with err while it is set.
type fakeAdmin struct {
	err error
	// beforeCreate runs at the start of each CreateUser.
	beforeCreate func(email string)
	created      []string
}

func (a *fakeAdmin) CreateUser(_ context.Context, email string) (string, error) {
	if a.beforeCreate != nil {
		a.beforeCreate(email)
	}
	if a.err != nil {
		return "", a.err
	}
	sub := uuid.NewString()
	a.created = append(a.created, sub)
	return sub, nil
}

func newService(t *testing.T, admin users.Admin) (*users.Service, *postgres.DB) {
	t.Helper()
	db, err := postgres.Open(context.Background(), pgtest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return users.New(db, nil, admin), db
}

func TestByEmailResolvesAnOperatorsInput(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, db := newService(t, &fakeAdmin{})
	created, err := svc.Create(ctx, "Admin@Example.com", tenancy.PlatformAdmin, tenancy.CustomerID{})
	if err != nil {
		t.Fatal(err)
	}

	got, err := svc.ByEmail(ctx, "  ADMIN@example.com ")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID() != created.User.ID() {
		t.Errorf("user = %s, want %s", got.ID(), created.User.ID())
	}

	if _, err := svc.ByEmail(ctx, "nobody@example.com"); !errors.Is(err, tenancy.ErrUserNotFound) {
		t.Errorf("unknown email: err = %v, want ErrUserNotFound", err)
	}

	customer, err := tenancy.NewCustomer(tenancy.CustomerID(uuid.New()), "c")
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "viewer@example.com", tenancy.Viewer, customer.ID())
	if err != nil {
		t.Fatal(err)
	}
	err = db.InTx(ctx, func(tx *postgres.Tx) error {
		if _, err := tx.CreateCustomer(ctx, customer); err != nil {
			return err
		}
		if _, err := tx.CreateUser(ctx, viewer, uuid.NewString()); err != nil {
			return err
		}
		_, err := tx.DisableUser(ctx, customer.ID(), viewer.ID())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ByEmail(ctx, "viewer@example.com"); !errors.Is(err, tenancy.ErrUserDisabled) {
		t.Errorf("disabled user: err = %v, want ErrUserDisabled", err)
	}
}

func TestCreateStoresThePlatformAdminBeforeInvitingThem(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{}
	svc, db := newService(t, admin)
	var storedFirst error
	admin.beforeCreate = func(email string) { _, storedFirst = svc.ByEmail(context.Background(), email) }

	created, err := svc.Create(context.Background(), "admin@example.com", tenancy.PlatformAdmin, tenancy.CustomerID{})
	if err != nil {
		t.Fatal(err)
	}

	if !errors.Is(storedFirst, tenancy.ErrUserPending) {
		t.Errorf("when Cognito is called: err = %v, want the User committed and pending", storedFirst)
	}
	stored := userBySub(t, db, admin.created[0])
	if stored != created.User || stored.Role() != tenancy.PlatformAdmin || created.Sub != admin.created[0] || stored.SignIn() != nil {
		t.Errorf("stored = %+v, created = %+v, want the platform admin stored under its sub and able to sign in", stored, created)
	}
}

func TestCreateWithATakenEmailInvitesNobody(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{}
	svc, _ := newService(t, admin)
	if _, err := svc.Create(context.Background(), "a@example.com", tenancy.PlatformAdmin, tenancy.CustomerID{}); err != nil {
		t.Fatal(err)
	}

	_, err := svc.Create(context.Background(), "A@example.com", tenancy.PlatformAdmin, tenancy.CustomerID{})

	if !errors.Is(err, tenancy.ErrEmailTaken) || len(admin.created) != 1 {
		t.Errorf("err = %v, invited %d, want ErrEmailTaken and only the first invitation", err, len(admin.created))
	}
}
