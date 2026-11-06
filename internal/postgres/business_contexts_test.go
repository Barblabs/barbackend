package postgres_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"barbackend/internal/business"
	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

func newAdmin(t *testing.T, db *postgres.DB, customer tenancy.CustomerID) tenancy.User {
	t.Helper()
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), uuid.NewString()+"@example.com", tenancy.CustomerAdmin, customer)
	if err != nil {
		t.Fatal(err)
	}
	inTx(t, db, func(tx *postgres.Tx) error {
		_, err := tx.CreateUser(context.Background(), u, uuid.NewString())
		return err
	})
	return u
}

func businessContext(t *testing.T, summary string) business.Context {
	t.Helper()
	c, err := business.New(business.Fields{
		Profile:   business.Profile{Summary: summary, Sectors: []business.Sector{"retail"}},
		Geography: business.Geography{Headquarters: "MX"},
		Operations: business.Operations{
			CriticalServices: []business.CriticalService{{Name: "Online store", Assets: []string{"web-01"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func saveBusinessContext(db *postgres.DB, customer tenancy.CustomerID, base int, c business.Context, u tenancy.User) (postgres.StoredBusinessContext, error) {
	return postgres.InTxValue(context.Background(), db, func(tx *postgres.Tx) (postgres.StoredBusinessContext, error) {
		return tx.SaveBusinessContext(context.Background(), customer, base, c, u)
	})
}

func getBusinessContext(t *testing.T, db *postgres.DB, customer tenancy.CustomerID) postgres.StoredBusinessContext {
	t.Helper()
	stored, err := postgres.InTxValue(context.Background(), db, func(tx *postgres.Tx) (postgres.StoredBusinessContext, error) {
		return tx.BusinessContext(context.Background(), customer)
	})
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func TestACustomerThatNeverSavedHasVersionZero(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)
	got := getBusinessContext(t, db, newCustomer(t, db))
	if got.Version != 0 || got.SavedBy != "" || !got.Saved.IsZero() || len(got.Context.Gaps()) != len(business.KeyFields()) {
		t.Errorf("stored = %+v, want version 0 with nothing stated", got)
	}
}

func TestEachSaveIsTheNextVersion(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)
	customer := newCustomer(t, db)
	admin := newAdmin(t, db, customer)

	first, err := saveBusinessContext(db, customer, 0, businessContext(t, "Shoes."), admin)
	if err != nil {
		t.Fatal(err)
	}
	second, err := saveBusinessContext(db, customer, first.Version, businessContext(t, "Shoes and bags."), admin)
	if err != nil {
		t.Fatal(err)
	}
	if first.Version != 1 || second.Version != 2 || second.SavedBy != admin.Email() {
		t.Errorf("versions %d and %d by %s, want 1 and 2 by %s", first.Version, second.Version, second.SavedBy, admin.Email())
	}

	got := getBusinessContext(t, db, customer)
	if got.Version != 2 || got.SavedBy != admin.Email() || !got.Saved.Equal(second.Saved) {
		t.Errorf("newest = version %d by %s at %v, want version 2 as saved", got.Version, got.SavedBy, got.Saved)
	}
	if want := businessContext(t, "Shoes and bags.").Fields(); !reflect.DeepEqual(got.Context.Fields(), want) {
		t.Errorf("newest = %+v, want %+v", got.Context.Fields(), want)
	}
}

func TestASaveOnAnOlderVersionIsStale(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)
	customer := newCustomer(t, db)
	admin := newAdmin(t, db, customer)
	if _, err := saveBusinessContext(db, customer, 0, businessContext(t, "Shoes."), admin); err != nil {
		t.Fatal(err)
	}

	for _, base := range []int{0, 2} {
		if _, err := saveBusinessContext(db, customer, base, businessContext(t, "Bags."), admin); !errors.Is(err, business.ErrStale) {
			t.Errorf("save on version %d: err = %v, want ErrStale", base, err)
		}
	}
	if got := getBusinessContext(t, db, customer); got.Version != 1 || got.Context.Fields().Profile.Summary != "Shoes." {
		t.Errorf("newest = version %d %q, want version 1 unchanged", got.Version, got.Context.Fields().Profile.Summary)
	}
}

func TestBusinessContextsAreTheirCustomers(t *testing.T) {
	t.Parallel()
	db, _ := newDBWithConn(t)
	customer, other := newCustomer(t, db), newCustomer(t, db)
	if _, err := saveBusinessContext(db, customer, 0, businessContext(t, "Shoes."), newAdmin(t, db, customer)); err != nil {
		t.Fatal(err)
	}
	if got := getBusinessContext(t, db, other); got.Version != 0 {
		t.Errorf("other Customer's version = %d, want 0", got.Version)
	}
	if _, err := saveBusinessContext(db, other, 0, businessContext(t, "Bags."), newAdmin(t, db, other)); err != nil {
		t.Errorf("first save of another Customer: %v", err)
	}
}
