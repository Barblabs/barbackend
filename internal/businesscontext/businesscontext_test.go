package businesscontext_test

import (
	"context"
	"errors"
	"testing"

	"barbackend/internal/business"
	"barbackend/internal/businesscontext"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

func TestOnlyASaveThatStoresNotifies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := postgres.Open(ctx, pgtest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	id := tenancy.CustomerID(uuid.New())
	customer, err := tenancy.NewCustomer(id, id.String())
	if err != nil {
		t.Fatal(err)
	}
	admin, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "admin@example.com", tenancy.CustomerAdmin, id)
	if err != nil {
		t.Fatal(err)
	}
	err = db.InTx(ctx, func(tx *postgres.Tx) error {
		if _, err := tx.CreateCustomer(ctx, customer); err != nil {
			return err
		}
		_, err := tx.CreateUser(ctx, admin, uuid.NewString())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := businesscontext.New(db)
	saves := 0
	svc.OnSaved(func() { saves++ })
	stated := business.Fields{Profile: business.Profile{Summary: "Pagos en línea."}}

	if _, err := svc.Save(ctx, admin, 0, stated); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Save(ctx, admin, 0, stated); !errors.Is(err, business.ErrStale) {
		t.Fatalf("a stale save: err = %v, want ErrStale", err)
	}
	if _, err := svc.Save(ctx, admin, 1, business.Fields{Profile: business.Profile{Sectors: []business.Sector{"nope"}}}); !errors.Is(err, business.ErrInvalidContext) {
		t.Fatalf("an invalid save: err = %v, want ErrInvalidContext", err)
	}

	if saves != 1 {
		t.Errorf("notices = %d, want only the save that stored", saves)
	}
}
