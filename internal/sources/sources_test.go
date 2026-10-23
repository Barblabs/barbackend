package sources_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"barbackend/internal/cmdb"
	"barbackend/internal/cmdb/cmdbtest"
	"barbackend/internal/encryption"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"github.com/google/uuid"
)

func TestAdd(t *testing.T) {
	tests := []struct {
		name        string
		provider    inventory.CMDBProvider
		settings    string
		credentials string
		want        error
	}{
		{"valid", fake, validSettings, validCredentials, nil},
		{"invalid settings", fake, `{}`, validCredentials, cmdbtest.ErrInvalidSettings},
		{"invalid credentials", fake, validSettings, `{}`, cmdbtest.ErrInvalidCredentials},
		{"unknown provider", "servicenow", validSettings, validCredentials, cmdb.ErrUnknownProvider},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			customer := newCustomer()

			src, err := e.sources.Add(context.Background(), customer, tt.provider, json.RawMessage(tt.settings), json.RawMessage(tt.credentials))

			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if n := e.queryInt(t, "SELECT count(*) FROM cmdb_sources"); (err == nil) != (n == 1) {
				t.Fatalf("stored sources = %d after err = %v", n, err)
			}
			if err != nil {
				return
			}
			err = e.db.InTx(context.Background(), func(tx *postgres.Tx) error {
				stored, err := tx.CMDBSource(context.Background(), src.ID())
				if err != nil {
					return err
				}
				if stored.Source != src || stored.Source.Customer() != customer || stored.Source.Provider() != fake {
					t.Errorf("stored source = %+v, want %+v of customer %v", stored.Source, src, customer)
				}
				if string(stored.Settings) != tt.settings {
					t.Errorf("settings = %s, want %s", stored.Settings, tt.settings)
				}
				if len(stored.Credentials) == 0 || bytes.Contains(stored.Credentials, []byte(cmdbtest.Secret)) {
					t.Errorf("stored credentials = %q, want ciphertext without the secret", stored.Credentials)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAddWithoutKeyStoresNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	_, err := e.withKey(encryption.Key{}).Add(context.Background(), newCustomer(), fake, json.RawMessage(validSettings), json.RawMessage(validCredentials))

	if !errors.Is(err, encryption.ErrNoKey) {
		t.Errorf("err = %v, want ErrNoKey", err)
	}
	if n := e.queryInt(t, "SELECT count(*) FROM cmdb_sources"); n != 0 {
		t.Errorf("stored sources = %d, want 0", n)
	}
}

func TestSync(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addSource(t)
	skipped := inventory.SkippedRecord{RecordID: "c", Reason: "no name"}
	e.provider.Snapshot = inventory.Snapshot{
		Records: []inventory.Record{record(t, "a", "vm-a"), record(t, "b", "vm-b")},
		Skipped: []inventory.SkippedRecord{skipped},
	}

	e.provider.Secret = ""

	first, err := e.sources.Sync(context.Background(), src.ID())
	if err != nil {
		t.Fatal(err)
	}
	if e.provider.Secret != cmdbtest.Secret {
		t.Errorf("provider got secret %q, want the decrypted %q", e.provider.Secret, cmdbtest.Secret)
	}
	if want := (inventory.SyncCounts{Created: 2, Skipped: 1}); first.Outcome() != inventory.SyncSucceeded || first.Counts() != want {
		t.Errorf("first run = %v %+v, want Succeeded %+v", first.Outcome(), first.Counts(), want)
	}
	if !reflect.DeepEqual(first.Skipped(), []inventory.SkippedRecord{skipped}) {
		t.Errorf("first run skipped = %+v, want [%+v]", first.Skipped(), skipped)
	}
	var reason string
	if err := e.conn.QueryRow(context.Background(), "SELECT skipped_records -> 0 ->> 'reason' FROM sync_runs").Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != skipped.Reason {
		t.Errorf("recorded skip reason = %q, want %q", reason, skipped.Reason)
	}

	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "a", "vm-a-renamed")}}
	second, err := e.sources.Sync(context.Background(), src.ID())
	if err != nil {
		t.Fatal(err)
	}
	if want := (inventory.SyncCounts{Updated: 1, Deactivated: 1}); second.Counts() != want {
		t.Errorf("second run counts = %+v, want %+v", second.Counts(), want)
	}
	if n := e.queryInt(t, "SELECT count(*) FROM sync_runs WHERE outcome_id = $1", int16(inventory.SyncSucceeded)); n != 2 {
		t.Errorf("successful runs = %d, want 2", n)
	}
	got := e.assets(t, src.ID())
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
			src := e.addSource(t)
			e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "a", "vm-a")}}
			if _, err := e.sources.Sync(context.Background(), src.ID()); err != nil {
				t.Fatal(err)
			}
			before := e.assets(t, src.ID())

			e.provider.Snapshot, e.provider.Err = tt.snapshot, tt.err
			_, err := e.sources.Sync(context.Background(), src.ID())

			if err == nil || (tt.err != nil && !errors.Is(err, tt.err)) {
				t.Fatalf("err = %v, want a failure wrapping %v", err, tt.err)
			}
			if got := e.assets(t, src.ID()); !reflect.DeepEqual(got, before) {
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

func TestSyncOfMissingSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if _, err := e.sources.Sync(context.Background(), inventory.CMDBSourceID(uuid.New())); !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestSyncOfUnregisteredProviderFails(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src, err := inventory.NewCMDBSource(inventory.CMDBSourceID(uuid.New()), newCustomer(), "removed")
	if err != nil {
		t.Fatal(err)
	}
	err = e.db.InTx(context.Background(), func(tx *postgres.Tx) error {
		return tx.CreateCMDBSource(context.Background(), src, json.RawMessage(`{}`), []byte{})
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := e.sources.Sync(context.Background(), src.ID()); !errors.Is(err, cmdb.ErrUnknownProvider) {
		t.Errorf("err = %v, want ErrUnknownProvider", err)
	}
	if n := e.queryInt(t, "SELECT count(*) FROM sync_runs WHERE outcome_id = $1", int16(inventory.SyncFailed)); n != 1 {
		t.Errorf("failed runs = %d, want 1", n)
	}
}

func TestSyncRevalidatesSettings(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addSource(t)
	if _, err := e.conn.Exec(context.Background(), "UPDATE cmdb_sources SET settings = '{}'"); err != nil {
		t.Fatal(err)
	}

	if _, err := e.sources.Sync(context.Background(), src.ID()); !errors.Is(err, cmdbtest.ErrInvalidSettings) {
		t.Errorf("err = %v, want cmdbtest.ErrInvalidSettings", err)
	}
	if n := e.queryInt(t, "SELECT count(*) FROM sync_runs WHERE outcome_id = $1", int16(inventory.SyncFailed)); n != 1 {
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
			src := e.addSource(t)
			e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "a", "vm-a")}}

			_, err := e.withKey(tt.key).Sync(context.Background(), src.ID())

			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if n := e.queryInt(t, "SELECT count(*) FROM sync_runs WHERE outcome_id = $1", int16(inventory.SyncFailed)); n != 1 {
				t.Errorf("failed runs = %d, want 1", n)
			}
			if got := e.assets(t, src.ID()); len(got) != 0 {
				t.Errorf("assets = %+v, want none", got)
			}
		})
	}
}

// Credentials are bound to their CMDB Source, so copying them to another
// row does not let it authenticate.
func TestSyncRejectsCredentialsOfAnotherSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	victim, attacker := e.addSource(t), e.addSource(t)
	_, err := e.conn.Exec(context.Background(), "UPDATE cmdb_sources SET credentials = (SELECT credentials FROM cmdb_sources WHERE id = $1) WHERE id = $2",
		uuid.UUID(victim.ID()), uuid.UUID(attacker.ID()))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := e.sources.Sync(context.Background(), attacker.ID()); !errors.Is(err, encryption.ErrCorrupt) {
		t.Errorf("err = %v, want ErrCorrupt", err)
	}
}
