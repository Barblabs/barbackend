package cmdb_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"barbackend/internal/cmdb"
	"barbackend/internal/cmdb/provider"
	"barbackend/internal/cmdb/provider/providertest"
	"barbackend/internal/encryption"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"github.com/google/uuid"
)

func TestSync(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	customer, src := e.connect(t)
	skipped := inventory.SkippedRecord{RecordID: "c", Reason: "no name"}
	e.provider.Snapshot = inventory.Snapshot{
		Records: []inventory.Record{record(t, "a", "vm-a"), record(t, "b", "vm-b")},
		Skipped: []inventory.SkippedRecord{skipped},
	}

	e.provider.Secret = ""

	first, err := e.cmdb.SyncConnected(context.Background(), customer)
	if err != nil {
		t.Fatal(err)
	}
	if e.provider.Secret != providertest.Secret {
		t.Errorf("provider got secret %q, want the decrypted %q", e.provider.Secret, providertest.Secret)
	}
	if want := (inventory.SyncCounts{Created: 2, Skipped: 1}); first.Outcome() != inventory.SyncSucceeded || first.Counts() != want {
		t.Errorf("first run = %v %+v, want Succeeded %+v", first.Outcome(), first.Counts(), want)
	}
	if !reflect.DeepEqual(first.Skipped(), []inventory.SkippedRecord{skipped}) {
		t.Errorf("first run skipped = %+v, want [%+v]", first.Skipped(), skipped)
	}
	var reason string
	if err := e.conn.QueryRow(context.Background(), "SELECT skipped_records -> 0 ->> 'reason' FROM sync_runs WHERE skipped_records <> '[]'").Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != skipped.Reason {
		t.Errorf("recorded skip reason = %q, want %q", reason, skipped.Reason)
	}

	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "a", "vm-a-renamed")}}
	second, err := e.cmdb.SyncConnected(context.Background(), customer)
	if err != nil {
		t.Fatal(err)
	}
	if want := (inventory.SyncCounts{Updated: 1, Deactivated: 1}); second.Counts() != want {
		t.Errorf("second run counts = %+v, want %+v", second.Counts(), want)
	}
	if n := e.queryInt(t, "SELECT count(*) FROM sync_runs WHERE outcome_id = $1", int16(inventory.SyncSucceeded)); n != 3 {
		t.Errorf("successful runs = %d, want 3 counting the first Sync of Connect", n)
	}
	got := e.assets(t, src)
	if len(got) != 2 || got[0].Imported().Name() != "vm-a-renamed" || !got[0].Active() || got[1].Active() {
		t.Errorf("assets = %+v, want a renamed and Active, b Inactive", got)
	}
}

func TestFailedSyncChangesNoAsset(t *testing.T) {
	errUnreachable := errors.New("cmdb unreachable")
	tests := []struct {
		name     string
		snapshot inventory.Snapshot
		err      error
	}{
		{"failed snapshot", inventory.Snapshot{}, errUnreachable},
		// Postgres rejects NUL in text, so the snapshot reconciles but fails to save.
		{"failed save", inventory.Snapshot{Records: []inventory.Record{record(t, "b", "vm\x00b")}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "a", "vm-a")}}
			customer, src := e.connect(t)
			before := e.assets(t, src)

			e.provider.Snapshot, e.provider.Err = tt.snapshot, tt.err
			_, err := e.cmdb.SyncConnected(context.Background(), customer)

			var failed *cmdb.SyncError
			if !errors.As(err, &failed) || (tt.err != nil && !errors.Is(err, tt.err)) {
				t.Fatalf("err = %v, want a *SyncError wrapping %v", err, tt.err)
			}
			if got := e.assets(t, src); !reflect.DeepEqual(got, before) {
				t.Errorf("assets = %+v, want unchanged %+v", got, before)
			}
			var failure string
			err = e.conn.QueryRow(context.Background(), "SELECT failure FROM sync_runs WHERE outcome_id = $1", int16(inventory.SyncFailed)).Scan(&failure)
			if err != nil {
				t.Fatalf("read failed run: %v", err)
			}
			if failure == "" {
				t.Error("failed run has no error")
			}
		})
	}
}

func TestSyncWithoutConnectedSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.connect(t)

	if _, err := e.cmdb.SyncConnected(context.Background(), newCustomer()); !errors.Is(err, cmdb.ErrNotConnected) {
		t.Errorf("err = %v, want ErrNotConnected", err)
	}
}

func TestSyncOfSourceDisconnectedWhileItRunsChangesNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "a", "vm-a")}}
	customer, src := e.connect(t)
	stored := func() [][]any {
		rows, err := e.conn.Query(context.Background(), `SELECT 'asset', record_id, name FROM assets WHERE cmdb_source_id = $1
			UNION ALL SELECT 'run', id::text, outcome_id::text FROM sync_runs WHERE cmdb_source_id = $1
			ORDER BY 1, 2`, uuid.UUID(src))
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var got [][]any
		for rows.Next() {
			values, err := rows.Values()
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, values)
		}
		return got
	}
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "a", "renamed"), record(t, "b", "vm-b")}}
	e.provider.BeforeSnapshot = func() {
		if err := e.cmdb.Disconnect(context.Background(), customer); err != nil {
			t.Error(err)
		}
	}
	before := stored()

	_, err := e.cmdb.SyncConnected(context.Background(), customer)

	if !errors.Is(err, cmdb.ErrNotConnected) {
		t.Errorf("err = %v, want ErrNotConnected", err)
	}
	if after := stored(); !reflect.DeepEqual(after, before) {
		t.Errorf("imported assets and sync runs = %v, want unchanged %v", after, before)
	}
}

func TestSyncOfUnregisteredProviderFails(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	customer := newCustomer()
	src, err := inventory.NewCMDBSource(inventory.CMDBSourceID(uuid.New()), customer, "removed")
	if err != nil {
		t.Fatal(err)
	}
	err = e.db.InTx(context.Background(), func(tx *postgres.Tx) error {
		return tx.CreateCMDBSource(context.Background(), src, json.RawMessage(`{}`), []byte{})
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := e.cmdb.SyncConnected(context.Background(), customer); !errors.Is(err, provider.ErrUnknownProvider) {
		t.Errorf("err = %v, want ErrUnknownProvider", err)
	}
	if n := e.failedRuns(t); n != 1 {
		t.Errorf("failed runs = %d, want 1", n)
	}
}

func TestSyncRevalidatesSettings(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	customer, _ := e.connect(t)
	if _, err := e.conn.Exec(context.Background(), "UPDATE cmdb_sources SET settings = '{}'"); err != nil {
		t.Fatal(err)
	}

	if _, err := e.cmdb.SyncConnected(context.Background(), customer); !errors.Is(err, providertest.ErrInvalidSettings) {
		t.Errorf("err = %v, want providertest.ErrInvalidSettings", err)
	}
	if n := e.failedRuns(t); n != 1 {
		t.Errorf("failed runs = %d, want 1", n)
	}
}

func TestSyncWithoutTheKeyFails(t *testing.T) {
	tests := []struct {
		name string
		key  encryption.Key
		want error
	}{
		{"no key", encryption.Key{}, encryption.ErrNoKey},
		{"another key", newKey(t), encryption.ErrWrongKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			customer, src := e.connect(t)
			e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "a", "vm-a")}}

			_, err := e.withKey(tt.key).SyncConnected(context.Background(), customer)

			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if n := e.failedRuns(t); n != 1 {
				t.Errorf("failed runs = %d, want 1", n)
			}
			if got := e.assets(t, src); len(got) != 0 {
				t.Errorf("assets = %+v, want none", got)
			}
		})
	}
}

func TestSyncRejectsCredentialsOfAnotherSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_, victim := e.connect(t)
	attacker, attackerSource := e.connect(t)
	_, err := e.conn.Exec(context.Background(), "UPDATE cmdb_sources SET credentials = (SELECT credentials FROM cmdb_sources WHERE id = $1) WHERE id = $2",
		uuid.UUID(victim), uuid.UUID(attackerSource))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := e.cmdb.SyncConnected(context.Background(), attacker); !errors.Is(err, encryption.ErrCorrupt) {
		t.Errorf("err = %v, want ErrCorrupt", err)
	}
}

func TestSyncOfDisconnectedSourceFails(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	customer, _ := e.connect(t)
	if err := e.cmdb.Disconnect(context.Background(), customer); err != nil {
		t.Fatal(err)
	}

	if _, err := e.cmdb.SyncConnected(context.Background(), customer); !errors.Is(err, cmdb.ErrNotConnected) {
		t.Errorf("err = %v, want ErrNotConnected", err)
	}
	if n := e.failedRuns(t); n != 0 {
		t.Errorf("failed runs = %d, want 0", n)
	}
}

func TestSyncWhileAnotherSyncRunsIsNotRecorded(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	customer, src := e.connect(t)
	release := e.holdSyncLock(t, src)

	_, err := e.cmdb.SyncConnected(context.Background(), customer)
	release()

	if !errors.Is(err, cmdb.ErrSyncInProgress) {
		t.Errorf("err = %v, want ErrSyncInProgress", err)
	}
	if got := e.connectedSource(t, customer); got.LastSyncFailure != nil {
		t.Errorf("last sync failure = %+v, want none, since the running Sync succeeded", got.LastSyncFailure)
	}
}

func TestSyncOutlivesItsCaller(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	customer, _ := e.connect(t)
	closedTab, cancel := context.WithCancel(context.Background())
	cancel()

	run, err := e.cmdb.SyncConnected(closedTab, customer)

	if err != nil {
		t.Fatal(err)
	}
	if got := e.connectedSource(t, customer); !got.LastSync.Equal(run.Finished().Truncate(time.Microsecond)) {
		t.Errorf("last sync = %v, want the Sync that finished at %v", got.LastSync, run.Finished())
	}
}

func TestSyncExceedingTheTimeLimitFails(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	customer, _ := e.connect(t)
	e.provider.Hanging = make(chan struct{})

	_, err := e.withSyncLimits(context.Background(), 50*time.Millisecond).SyncConnected(context.Background(), customer)

	e.wantFailedSync(t, customer, err, context.DeadlineExceeded)
}

func TestSyncCanceledByShutdownFails(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	lifetime, shutdown := context.WithCancel(context.Background())
	defer shutdown()
	customer, _ := e.connect(t)
	e.provider.Hanging = make(chan struct{})
	go func() {
		<-e.provider.Hanging
		shutdown()
	}()

	_, err := e.withSyncLimits(lifetime, time.Minute).SyncConnected(context.Background(), customer)

	e.wantFailedSync(t, customer, err, context.Canceled)
}

func (e env) wantFailedSync(t *testing.T, customer inventory.CustomerID, err, cause error) {
	t.Helper()
	var failed *cmdb.SyncError
	if !errors.As(err, &failed) || !errors.Is(err, cause) {
		t.Errorf("err = %v, want a *SyncError wrapping %v", err, cause)
	}
	if got := e.connectedSource(t, customer); got.LastSyncFailure == nil || !strings.Contains(got.LastSyncFailure.Error, cause.Error()) {
		t.Errorf("last sync failure = %+v, want %v", got.LastSyncFailure, cause)
	}
}
