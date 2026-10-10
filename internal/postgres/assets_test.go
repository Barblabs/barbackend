package postgres_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
)

func fullParams() inventory.ImportedAssetParams {
	return inventory.ImportedAssetParams{
		Name:        "srv-01",
		Description: "Billing API",
		Kind:        inventory.Server,
		Hardware:    &inventory.Hardware{Vendor: "Dell", Model: ""},
		Software: []inventory.SoftwareComponent{
			{Role: inventory.Application, Name: "nginx", Version: "1.24", Product: &inventory.Product{Vendor: "f5", Name: "nginx"}},
			{Role: inventory.OperatingSystem, Name: "Ubuntu", Version: "22.04 LTS"},
			{Role: inventory.Application, Name: "custom agent"},
		},
		Criticality: inventory.CriticalityHigh,
		Owner:       "owner@example.com",
		Retired:     true,
	}
}

func TestAssetRoundTrip(t *testing.T) {
	minimal := inventory.ImportedAssetParams{Name: "vm-01", Kind: inventory.VirtualMachine}
	tests := []struct {
		name     string
		imported inventory.ImportedAssetParams
		state    inventory.AssetState
	}{
		{"minimal and active", minimal, inventory.AssetState{Active: true}},
		{"everything set and inactive", fullParams(), inventory.AssetState{DeclaredOwner: "declared@example.com", DeclaredExposure: inventory.InternetFacing}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db := pgtest.NewDB(t)
			src := newSource(t, db, newCustomer())
			want, err := inventory.RestoreAsset(inventory.SourceReference{Source: src.ID(), RecordID: "42"}, mustImported(t, tt.imported), tt.state)
			if err != nil {
				t.Fatal(err)
			}

			inTx(t, db, func(tx *postgres.Tx) error { return tx.CreateAsset(context.Background(), want) })

			got := assets(t, db, src.ID())
			if len(got) != 1 || !reflect.DeepEqual(got[0], want) {
				t.Errorf("assets = %+v, want [%+v]", got, want)
			}
		})
	}
}

func TestAssetOwnersAreSharedWithinACustomer(t *testing.T) {
	t.Parallel()
	db, conn := newDBWithConn(t)
	customer := newCustomer()
	first := newSource(t, db, customer)
	second := newSource(t, db, customer)
	other := newSource(t, db, newCustomer())

	p := inventory.ImportedAssetParams{Name: "pc", Kind: inventory.Workstation, Owner: "owner@example.com"}
	inTx(t, db, func(tx *postgres.Tx) error {
		for i, src := range []inventory.CMDBSource{first, first, second, other} {
			a, err := inventory.NewAsset(inventory.SourceReference{Source: src.ID(), RecordID: string(rune('a' + i))}, mustImported(t, p))
			if err != nil {
				return err
			}
			if i == 1 {
				if err := a.DeclareOwner("owner@example.com"); err != nil {
					return err
				}
			}
			if err := tx.CreateAsset(context.Background(), a); err != nil {
				return err
			}
		}
		return nil
	})

	if n := queryInt(t, conn, "SELECT count(*) FROM asset_owners WHERE customer_id = $1", customer.String()); n != 1 {
		t.Errorf("owners of the customer = %d, want 1", n)
	}
	if n := queryInt(t, conn, "SELECT count(*) FROM asset_owners"); n != 2 {
		t.Errorf("owners overall = %d, want 2 (one per customer)", n)
	}
}

func TestUpdateImportedKeepsStateAndDeclarations(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	src := newSource(t, db, newCustomer())
	ref := inventory.SourceReference{Source: src.ID(), RecordID: "1"}
	state := inventory.AssetState{DeclaredOwner: "declared@example.com", DeclaredExposure: inventory.Internal}
	stored, err := inventory.RestoreAsset(ref, mustImported(t, fullParams()), state)
	if err != nil {
		t.Fatal(err)
	}
	inTx(t, db, func(tx *postgres.Tx) error { return tx.CreateAsset(context.Background(), stored) })

	// The caller's Asset differs in state and Declarations: only its imported values must be written.
	changed := inventory.ImportedAssetParams{
		Name:     "srv-01-renamed",
		Kind:     inventory.Server,
		Software: []inventory.SoftwareComponent{{Role: inventory.OperatingSystem, Name: "Ubuntu", Version: "24.04 LTS"}},
	}
	update, err := inventory.NewAsset(ref, mustImported(t, changed))
	if err != nil {
		t.Fatal(err)
	}
	inTx(t, db, func(tx *postgres.Tx) error { return tx.UpdateImported(context.Background(), update) })

	want, err := inventory.RestoreAsset(ref, mustImported(t, changed), state)
	if err != nil {
		t.Fatal(err)
	}
	if got := assets(t, db, src.ID()); len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Errorf("assets = %+v, want [%+v]", got, want)
	}
}

func TestUpdateActiveKeepsFirstInactiveTime(t *testing.T) {
	t.Parallel()
	db, conn := newDBWithConn(t)
	src := newSource(t, db, newCustomer())
	a, err := inventory.NewAsset(inventory.SourceReference{Source: src.ID(), RecordID: "1"}, mustImported(t, fullParams()))
	if err != nil {
		t.Fatal(err)
	}
	inTx(t, db, func(tx *postgres.Tx) error { return tx.CreateAsset(context.Background(), a) })

	inactiveSince := func() *time.Time {
		var ts *time.Time
		if err := conn.QueryRow(context.Background(), "SELECT inactive_since FROM assets").Scan(&ts); err != nil {
			t.Fatal(err)
		}
		return ts
	}
	setActive := func(active bool) {
		if active {
			a.Reactivate()
		} else {
			a.MarkInactive()
		}
		inTx(t, db, func(tx *postgres.Tx) error { return tx.UpdateActive(context.Background(), a) })
	}

	setActive(false)
	first := inactiveSince()
	if first == nil {
		t.Fatal("inactive_since is NULL after marking inactive")
	}
	setActive(false)
	if again := inactiveSince(); again == nil || !again.Equal(*first) {
		t.Errorf("inactive_since = %v after staying inactive, want %v", again, first)
	}
	setActive(true)
	if ts := inactiveSince(); ts != nil {
		t.Errorf("inactive_since = %v after reactivating, want NULL", ts)
	}
	if got := assets(t, db, src.ID()); !got[0].Active() {
		t.Error("reloaded asset is inactive, want active")
	}
}

func TestUpdatesOfMissingAssetFail(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	src := newSource(t, db, newCustomer())
	a, err := inventory.NewAsset(inventory.SourceReference{Source: src.ID(), RecordID: "missing"}, mustImported(t, fullParams()))
	if err != nil {
		t.Fatal(err)
	}
	updates := map[string]func(*postgres.Tx) error{
		"imported": func(tx *postgres.Tx) error { return tx.UpdateImported(context.Background(), a) },
		"active":   func(tx *postgres.Tx) error { return tx.UpdateActive(context.Background(), a) },
	}
	for name, update := range updates {
		t.Run(name, func(t *testing.T) {
			if err := db.InTx(context.Background(), update); !errors.Is(err, postgres.ErrNotFound) {
				t.Errorf("err = %v, want ErrNotFound", err)
			}
		})
	}
}
