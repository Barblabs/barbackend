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
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func fullParams(t *testing.T) inventory.ImportedAssetParams {
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
		Owner:       mustOwner(t, "owner@example.com"),
		Retired:     true,
	}
}

func record(t *testing.T, id string, p inventory.ImportedAssetParams) inventory.Record {
	return inventory.Record{RecordID: id, Imported: mustImported(t, p)}
}

func TestCreatedAssetRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		imported inventory.ImportedAssetParams
	}{
		{"minimal and active", inventory.ImportedAssetParams{Name: "vm-01", Kind: inventory.VirtualMachine}},
		{"everything set and inactive", fullParams(t)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db := pgtest.NewDB(t)
			src := newSource(t, db, newCustomer())

			r := syncRecords(t, db, src.ID(), record(t, "42", tt.imported))

			want := r.Changes()[0].Asset
			if got := assets(t, db, src.ID()); len(got) != 1 || !reflect.DeepEqual(got[0], want) {
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
	p := inventory.ImportedAssetParams{Name: "pc", Kind: inventory.Workstation, Owner: mustOwner(t, "owner@example.com")}

	syncRecords(t, db, first.ID(), record(t, "a", p), record(t, "b", p))
	syncRecords(t, db, second.ID(), record(t, "a", p))
	syncRecords(t, db, other.ID(), record(t, "a", p))

	if n := queryInt(t, conn, "SELECT count(*) FROM asset_owners WHERE customer_id = $1", customer.String()); n != 1 {
		t.Errorf("owners of the customer = %d, want 1", n)
	}
	if n := queryInt(t, conn, "SELECT count(*) FROM asset_owners"); n != 2 {
		t.Errorf("owners overall = %d, want 2 (one per customer)", n)
	}
}

func TestImportedUpdateKeepsDeclarations(t *testing.T) {
	t.Parallel()
	db, conn := newDBWithConn(t)
	src := newSource(t, db, newCustomer())
	syncRecords(t, db, src.ID(), record(t, "1", fullParams(t)))
	_, err := conn.Exec(context.Background(), `
		WITH owner AS (
			INSERT INTO asset_owners (customer_id, email) VALUES ($1, 'declared@example.com') RETURNING id
		)
		UPDATE assets SET declared_owner_id = (SELECT id FROM owner), declared_exposure_id = $2`,
		src.Customer().String(), int16(inventory.Internal))
	if err != nil {
		t.Fatal(err)
	}

	changed := inventory.ImportedAssetParams{
		Name:     "srv-01-renamed",
		Kind:     inventory.Server,
		Software: []inventory.SoftwareComponent{{Role: inventory.OperatingSystem, Name: "Ubuntu", Version: "24.04 LTS"}},
	}
	syncRecords(t, db, src.ID(), record(t, "1", changed))

	want, err := inventory.RestoreAsset(inventory.SourceReference{Source: src.ID(), RecordID: "1"}, mustImported(t, changed), inventory.AssetState{
		Active:           true,
		DeclaredOwner:    mustOwner(t, "declared@example.com"),
		DeclaredExposure: inventory.Internal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := assets(t, db, src.ID()); len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Errorf("assets = %+v, want [%+v]", got, want)
	}
}

func TestDeactivationKeepsFirstInactiveTime(t *testing.T) {
	t.Parallel()
	db, conn := newDBWithConn(t)
	src := newSource(t, db, newCustomer())
	retired := fullParams(t)
	syncRecords(t, db, src.ID(), record(t, "1", retired))
	inactiveSince := func() *time.Time {
		var ts *time.Time
		if err := conn.QueryRow(context.Background(), "SELECT inactive_since FROM assets").Scan(&ts); err != nil {
			t.Fatal(err)
		}
		return ts
	}
	first := inactiveSince()
	if first == nil {
		t.Fatal("inactive_since is NULL for an Asset created Inactive")
	}

	// A reconciliation that still sees the Asset as Active deactivates it again.
	stale := restore(t, src.ID(), "1", retired, true)
	inSource(t, db, src.ID(), func(tx *postgres.SourceTx) error {
		r, err := inventory.Reconcile(src.ID(), []*inventory.Asset{stale}, inventory.Snapshot{})
		if err != nil {
			return err
		}
		return save(tx, r)
	})
	if again := inactiveSince(); again == nil || !again.Equal(*first) {
		t.Errorf("inactive_since = %v after deactivating again, want %v", again, first)
	}

	unretired := retired
	unretired.Retired = false
	syncRecords(t, db, src.ID(), record(t, "1", unretired))
	if ts := inactiveSince(); ts != nil {
		t.Errorf("inactive_since = %v after reactivating, want NULL", ts)
	}
}

func restore(t *testing.T, src inventory.CMDBSourceID, recordID string, p inventory.ImportedAssetParams, active bool) *inventory.Asset {
	t.Helper()
	a, err := inventory.RestoreAsset(inventory.SourceReference{Source: src, RecordID: recordID}, mustImported(t, p), inventory.AssetState{Active: active})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestSaveOfMissingAssetFails(t *testing.T) {
	active := inventory.ImportedAssetParams{Name: "vm", Kind: inventory.VirtualMachine}
	renamed := active
	renamed.Name = "vm-renamed"
	tests := []struct {
		name     string
		active   bool
		snapshot []inventory.ImportedAssetParams
	}{
		{"imported update", true, []inventory.ImportedAssetParams{renamed}},
		{"deactivation", true, nil},
		{"reactivation", false, []inventory.ImportedAssetParams{active}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db := pgtest.NewDB(t)
			src := newSource(t, db, newCustomer())
			var s inventory.Snapshot
			for _, p := range tt.snapshot {
				s.Records = append(s.Records, record(t, "missing", p))
			}

			err := db.InLockedSource(context.Background(), src.ID(), time.Now(), func(tx *postgres.SourceTx) error {
				r, err := inventory.Reconcile(src.ID(), []*inventory.Asset{restore(t, src.ID(), "missing", active, tt.active)}, s)
				if err != nil {
					return err
				}
				return save(tx, r)
			})
			if !errors.Is(err, postgres.ErrNotFound) {
				t.Errorf("err = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestInLockedSourceOfMissingSource(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	err := db.InLockedSource(context.Background(), inventory.CMDBSourceID(uuid.New()), time.Now(), func(*postgres.SourceTx) error { return nil })
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestInLockedSourceRejectsSupersededSync(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	src := newSource(t, db, newCustomer())
	start := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	later := start.Add(time.Hour)
	recordRun := func(run inventory.SyncRun, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		inTx(t, db, func(tx *postgres.Tx) error { return tx.RecordSyncRun(context.Background(), run) })
	}
	lock := func(startedAt time.Time) error {
		return db.InLockedSource(context.Background(), src.ID(), startedAt, func(*postgres.SourceTx) error { return nil })
	}

	recordRun(inventory.FailedRun(src.ID(), later, later, errors.New("cmdb unreachable")))
	if err := lock(start); err != nil {
		t.Errorf("after a later failed run: err = %v, want nil", err)
	}

	r, err := inventory.Reconcile(src.ID(), nil, inventory.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	recordRun(inventory.SucceededRun(r, later, later))
	if err := lock(start); !errors.Is(err, postgres.ErrSuperseded) {
		t.Errorf("after a later successful run: err = %v, want ErrSuperseded", err)
	}
	if err := lock(later.Add(time.Second)); err != nil {
		t.Errorf("after an earlier successful run: err = %v, want nil", err)
	}
}

func TestInLockedSourceBlocksASecondTransaction(t *testing.T) {
	t.Parallel()
	url := pgtest.URL(t)
	open := func(url string) *postgres.DB {
		db, err := postgres.Open(context.Background(), url)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		return db
	}
	db := open(url)
	impatient := open(url + "&lock_timeout=100ms")
	src := newSource(t, db, newCustomer())

	locked, release := make(chan struct{}), make(chan struct{})
	done := make(chan error)
	go func() {
		done <- db.InLockedSource(context.Background(), src.ID(), time.Now(), func(*postgres.SourceTx) error {
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked

	err := impatient.InLockedSource(context.Background(), src.ID(), time.Now(), func(*postgres.SourceTx) error { return nil })
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("err = %v, want lock_not_available (55P03)", err)
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := impatient.InLockedSource(context.Background(), src.ID(), time.Now(), func(*postgres.SourceTx) error { return nil }); err != nil {
		t.Errorf("after release: err = %v, want nil", err)
	}
}
