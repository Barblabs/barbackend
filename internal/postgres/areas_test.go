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

func areaRecord(t *testing.T, id, name string, inactive bool) inventory.AreaRecord {
	t.Helper()
	imported, err := inventory.NewImportedArea(inventory.ImportedAreaParams{Name: name, Inactive: inactive})
	if err != nil {
		t.Fatal(err)
	}
	return inventory.AreaRecord{RecordID: id, Imported: imported}
}

func inArea(area string) inventory.ImportedAssetParams {
	return inventory.ImportedAssetParams{Name: "vm", Kind: inventory.VirtualMachine, Area: area}
}

func TestAreasRoundTrip(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	src := newSource(t, db, newCustomer(t, db))
	areas := []inventory.AreaRecord{areaRecord(t, "1", "IT", false), areaRecord(t, "2", "Legacy", true)}

	r := syncSnapshot(t, db, src.ID(), inventory.Snapshot{Areas: areas, Records: []inventory.Record{record(t, "42", inArea("1"))}})

	want := inventory.Stored{Assets: r.Created(), Areas: r.Areas().Created}
	if got := stored(t, db, src.ID()); !reflect.DeepEqual(got, want) {
		t.Errorf("stored = %+v, want %+v", got, want)
	}

	r = syncSnapshot(t, db, src.ID(), inventory.Snapshot{Areas: areas, Records: []inventory.Record{record(t, "42", inArea("2"))}})

	if len(r.Updated()) != 1 {
		t.Fatalf("updated = %d assets, want 1 for a changed Area", len(r.Updated()))
	}
	if got := assets(t, db, src.ID()); len(got) != 1 || !reflect.DeepEqual(got[0], r.Updated()[0]) {
		t.Errorf("assets = %+v, want [%+v]", got, r.Updated()[0])
	}
}

func TestSyncKeepsAreaOwner(t *testing.T) {
	t.Parallel()
	db, conn := newDBWithConn(t)
	src := newSource(t, db, newCustomer(t, db))
	syncSnapshot(t, db, src.ID(), inventory.Snapshot{Areas: []inventory.AreaRecord{areaRecord(t, "1", "IT", false)}})
	if _, err := conn.Exec(context.Background(), "UPDATE customer_areas SET owner_email = 'owner@example.com'"); err != nil {
		t.Fatal(err)
	}
	check := func(step, name string, active bool) {
		t.Helper()
		got := stored(t, db, src.ID()).Areas
		if len(got) != 1 {
			t.Fatalf("%s: areas = %+v, want one", step, got)
		}
		owner, ok := got[0].Owner()
		if got[0].Name() != name || got[0].Active() != active || !ok || owner != mustOwner(t, "owner@example.com") {
			t.Errorf("%s: area = %q active %v owner %v, want %q active %v owner@example.com",
				step, got[0].Name(), got[0].Active(), owner, name, active)
		}
	}

	renamed := inventory.Snapshot{Areas: []inventory.AreaRecord{areaRecord(t, "1", "IT Department", false)}}
	syncSnapshot(t, db, src.ID(), renamed)
	check("renamed", "IT Department", true)

	syncSnapshot(t, db, src.ID(), inventory.Snapshot{})
	check("absent", "IT Department", false)

	syncSnapshot(t, db, src.ID(), renamed)
	check("back", "IT Department", true)
}

func TestAreaDeactivationKeepsFirstInactiveTime(t *testing.T) {
	t.Parallel()
	db, conn := newDBWithConn(t)
	src := newSource(t, db, newCustomer(t, db))
	inactiveSince := func() *time.Time {
		var ts *time.Time
		if err := conn.QueryRow(context.Background(), "SELECT inactive_since FROM customer_areas").Scan(&ts); err != nil {
			t.Fatal(err)
		}
		return ts
	}
	syncSnapshot(t, db, src.ID(), inventory.Snapshot{Areas: []inventory.AreaRecord{areaRecord(t, "1", "IT", true)}})
	first := inactiveSince()
	if first == nil {
		t.Fatal("inactive_since is NULL for an Area created Inactive")
	}

	syncSnapshot(t, db, src.ID(), inventory.Snapshot{})
	if again := inactiveSince(); again == nil || !again.Equal(*first) {
		t.Errorf("inactive_since = %v after deactivating again, want %v", again, first)
	}
}

func TestFailedSyncLeavesAreasUnchanged(t *testing.T) {
	tests := []struct {
		name     string
		snapshot func(t *testing.T) inventory.Snapshot
	}{
		{"failed reconcile", func(t *testing.T) inventory.Snapshot {
			return inventory.Snapshot{
				Areas:   []inventory.AreaRecord{areaRecord(t, "1", "IT Department", false)},
				Records: []inventory.Record{record(t, "42", inArea("unknown"))},
			}
		}},
		// Postgres rejects NUL in text, so the Areas are saved before the
		// Asset fails.
		{"failed save", func(t *testing.T) inventory.Snapshot {
			nul := inArea("2")
			nul.Name = "vm\x00"
			return inventory.Snapshot{
				Areas:   []inventory.AreaRecord{areaRecord(t, "1", "IT Department", false), areaRecord(t, "2", "Ops", false)},
				Records: []inventory.Record{record(t, "42", nul)},
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db := pgtest.NewDB(t)
			src := newSource(t, db, newCustomer(t, db))
			syncSnapshot(t, db, src.ID(), inventory.Snapshot{
				Areas:   []inventory.AreaRecord{areaRecord(t, "1", "IT", false)},
				Records: []inventory.Record{record(t, "42", inArea("1"))},
			})
			before := stored(t, db, src.ID())

			_, err := db.CommitSync(context.Background(), src.ID(), time.Now(), reconcileWith(src.ID(), tt.snapshot(t)))

			if err == nil {
				t.Fatal("err = nil, want the Sync to fail")
			}
			if got := stored(t, db, src.ID()); !reflect.DeepEqual(got, before) {
				t.Errorf("stored = %+v, want unchanged %+v", got, before)
			}
		})
	}
}

func TestSaveOfMissingAreaFails(t *testing.T) {
	tests := []struct {
		name     string
		active   bool
		snapshot []inventory.AreaRecord
	}{
		{"rename", true, []inventory.AreaRecord{areaRecord(t, "missing", "IT Department", false)}},
		{"deactivation", true, nil},
		{"reactivation", false, []inventory.AreaRecord{areaRecord(t, "missing", "IT", false)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db := pgtest.NewDB(t)
			src := newSource(t, db, newCustomer(t, db))
			ref := inventory.SourceReference{Source: src.ID(), RecordID: "missing"}
			ghost, err := inventory.RestoreArea(ref, "IT", inventory.AreaState{Active: tt.active})
			if err != nil {
				t.Fatal(err)
			}

			_, err = db.CommitSync(context.Background(), src.ID(), time.Now(), func(inventory.Stored) (inventory.Reconciliation, error) {
				return inventory.Reconcile(src.ID(), inventory.Stored{Areas: []*inventory.Area{ghost}}, inventory.Snapshot{Areas: tt.snapshot})
			})

			if !errors.Is(err, postgres.ErrNotFound) {
				t.Errorf("err = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestDisconnectDeactivatesAreas(t *testing.T) {
	t.Parallel()
	db, conn := newDBWithConn(t)
	customer := newCustomer(t, db)
	src := newSource(t, db, customer)
	syncSnapshot(t, db, src.ID(), inventory.Snapshot{Areas: []inventory.AreaRecord{areaRecord(t, "1", "IT", false)}})

	inTx(t, db, func(tx *postgres.Tx) error { return tx.DisconnectCMDBSource(context.Background(), customer) })

	if n := queryInt(t, conn, "SELECT count(*) FROM customer_areas WHERE inactive_since IS NULL"); n != 0 {
		t.Errorf("active areas after disconnect = %d, want 0", n)
	}
}
