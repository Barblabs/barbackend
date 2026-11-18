package areas_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"barbackend/internal/areas"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

type env struct {
	db    *postgres.DB
	areas *areas.Service
}

func newEnv(t *testing.T) env {
	t.Helper()
	db := pgtest.NewDB(t)
	return env{db: db, areas: areas.New(db)}
}

func (e env) inTx(t *testing.T, fn func(*postgres.Tx) error) {
	t.Helper()
	if err := e.db.InTx(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

func (e env) newCustomer(t *testing.T) tenancy.CustomerID {
	t.Helper()
	id := tenancy.CustomerID(uuid.New())
	c, err := tenancy.NewCustomer(id, id.String())
	if err != nil {
		t.Fatal(err)
	}
	e.inTx(t, func(tx *postgres.Tx) error {
		_, err := tx.CreateCustomer(context.Background(), c)
		return err
	})
	return id
}

// connect connects a CMDB Source for customer and syncs areas into it.
func (e env) connect(t *testing.T, customer tenancy.CustomerID, areas ...inventory.AreaRecord) inventory.CMDBSourceID {
	t.Helper()
	src, err := inventory.NewCMDBSource(inventory.CMDBSourceID(uuid.New()), customer, "itop")
	if err != nil {
		t.Fatal(err)
	}
	e.inTx(t, func(tx *postgres.Tx) error {
		return tx.CreateCMDBSource(context.Background(), src, []byte(`{}`), []byte{})
	})
	e.sync(t, src.ID(), areas...)
	return src.ID()
}

func (e env) sync(t *testing.T, src inventory.CMDBSourceID, areas ...inventory.AreaRecord) {
	t.Helper()
	_, err := e.db.CommitSync(context.Background(), src, time.Now(), func(existing inventory.Stored) (inventory.Reconciliation, error) {
		return inventory.Reconcile(src, existing, inventory.Snapshot{Areas: areas})
	})
	if err != nil {
		t.Fatal(err)
	}
}

// only lists the Customer's Areas, of which there must be one.
func (e env) only(t *testing.T, customer tenancy.CustomerID) areas.StoredArea {
	t.Helper()
	got, err := e.areas.List(context.Background(), user(t, tenancy.Viewer, customer), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("areas = %s, want one", names(got))
	}
	return got[0]
}

func ownerOf(a areas.StoredArea) string {
	owner, ok := a.Area.Owner()
	if !ok {
		return "none"
	}
	return owner.String()
}

func (e env) disconnect(t *testing.T, customer tenancy.CustomerID) {
	t.Helper()
	e.inTx(t, func(tx *postgres.Tx) error { return tx.DisconnectCMDBSource(context.Background(), customer) })
}

func area(t *testing.T, id, name string, inactive bool) inventory.AreaRecord {
	t.Helper()
	imported, err := inventory.NewImportedArea(inventory.ImportedAreaParams{Name: name, Inactive: inactive})
	if err != nil {
		t.Fatal(err)
	}
	return inventory.AreaRecord{RecordID: id, Imported: imported}
}

func user(t *testing.T, role tenancy.Role, customer tenancy.CustomerID) tenancy.User {
	t.Helper()
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "user@example.com", role, customer)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func names(stored []areas.StoredArea) string {
	var got []string
	for _, a := range stored {
		got = append(got, a.Area.Name())
	}
	return fmt.Sprint(got)
}

func TestListFiltersByActiveAndSortsByName(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	customer := e.newCustomer(t)
	e.connect(t, customer, area(t, "1", "Sales", false), area(t, "2", "IT", false), area(t, "3", "Legacy", true))
	viewer := user(t, tenancy.Viewer, customer)

	tests := []struct {
		name   string
		active *bool
		want   string
	}{
		{"all", nil, "[IT Legacy Sales]"},
		{"active", new(true), "[IT Sales]"},
		{"inactive", new(false), "[Legacy]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := e.areas.List(context.Background(), viewer, tt.active)
			if err != nil {
				t.Fatal(err)
			}
			if names(got) != tt.want {
				t.Errorf("areas = %s, want %s", names(got), tt.want)
			}
		})
	}
}

func TestListIncludesAreasOfDisconnectedSourcesAsInactive(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	customer := e.newCustomer(t)
	e.connect(t, customer, area(t, "1", "Old", false))
	e.disconnect(t, customer)
	e.connect(t, customer, area(t, "1", "New", false))

	got, err := e.areas.List(context.Background(), user(t, tenancy.Viewer, customer), nil)
	if err != nil {
		t.Fatal(err)
	}

	if names(got) != "[New Old]" || !got[0].Area.Active() || got[1].Area.Active() || got[1].InactiveSince == nil {
		t.Errorf("areas = %+v, want New active and Old inactive", got)
	}
	if got[0].ID == got[1].ID {
		t.Errorf("both areas have id %d, want one each", got[0].ID)
	}
}

func TestListOnlyReturnsTheCustomersAreas(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	mine, theirs := e.newCustomer(t), e.newCustomer(t)
	e.connect(t, mine, area(t, "1", "Mine", false))
	e.connect(t, theirs, area(t, "1", "Theirs", false))

	got, err := e.areas.List(context.Background(), user(t, tenancy.Viewer, mine), nil)
	if err != nil {
		t.Fatal(err)
	}

	if names(got) != "[Mine]" {
		t.Errorf("areas = %s, want only Mine", names(got))
	}
}

func TestListRefusesAPlatformAdmin(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	_, err := e.areas.List(context.Background(), user(t, tenancy.PlatformAdmin, tenancy.CustomerID{}), nil)

	if !errors.Is(err, tenancy.ErrNoCustomer) {
		t.Errorf("err = %v, want ErrNoCustomer", err)
	}
}

func TestSetOwnerStatesTheCanonicalEmailAndASyncKeepsIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	customer := e.newCustomer(t)
	src := e.connect(t, customer, area(t, "1", "IT", false))
	admin := user(t, tenancy.CustomerAdmin, customer)

	set, err := e.areas.SetOwner(context.Background(), admin, e.only(t, customer).ID, new("  Ana@Example.COM "))
	if err != nil {
		t.Fatal(err)
	}
	e.sync(t, src, area(t, "1", "Information Technology", false))

	if ownerOf(set) != "ana@example.com" {
		t.Errorf("owner after setting = %s, want ana@example.com", ownerOf(set))
	}
	if got := e.only(t, customer); got.Area.Name() != "Information Technology" || ownerOf(got) != "ana@example.com" {
		t.Errorf("area after a renaming Sync = %s owned by %s, want the new name and the owner kept", got.Area.Name(), ownerOf(got))
	}
}

func TestSetOwnerWithNoEmailClearsIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	customer := e.newCustomer(t)
	e.connect(t, customer, area(t, "1", "IT", false))
	admin := user(t, tenancy.CustomerAdmin, customer)
	id := e.only(t, customer).ID
	if _, err := e.areas.SetOwner(context.Background(), admin, id, new("ana@example.com")); err != nil {
		t.Fatal(err)
	}

	if _, err := e.areas.SetOwner(context.Background(), admin, id, nil); err != nil {
		t.Fatal(err)
	}

	if got := ownerOf(e.only(t, customer)); got != "none" {
		t.Errorf("owner after clearing = %s, want none", got)
	}
}

func TestSetOwnerOfAnotherCustomersAreaIsNotFound(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	mine, theirs := e.newCustomer(t), e.newCustomer(t)
	e.connect(t, theirs, area(t, "1", "Theirs", false))
	id := e.only(t, theirs).ID

	_, err := e.areas.SetOwner(context.Background(), user(t, tenancy.CustomerAdmin, mine), id, new("ana@example.com"))

	if !errors.Is(err, areas.ErrAreaNotFound) {
		t.Errorf("err = %v, want ErrAreaNotFound", err)
	}
	if got := ownerOf(e.only(t, theirs)); got != "none" {
		t.Errorf("their owner = %s, want none", got)
	}
}
