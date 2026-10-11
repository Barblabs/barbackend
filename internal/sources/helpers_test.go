package sources_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"barbackend/internal/cmdb"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/sources"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const fake inventory.CMDBProvider = "fake"

var errInvalidSettings = errors.New("settings need a url")

// fakeProvider returns whatever snapshot or error the test sets.
type fakeProvider struct {
	snapshot inventory.Snapshot
	err      error
}

func (f *fakeProvider) ParseSettings(settings json.RawMessage) (cmdb.Settings, error) {
	var s struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(settings, &s); err != nil || s.URL == "" {
		return nil, errInvalidSettings
	}
	return f, nil
}

func (f *fakeProvider) Snapshot(context.Context) (inventory.Snapshot, error) {
	return f.snapshot, f.err
}

type env struct {
	db       *postgres.DB
	conn     *pgx.Conn
	provider *fakeProvider
	sources  *sources.Service
}

func newEnv(t *testing.T) env {
	t.Helper()
	url := pgtest.URL(t)
	db, err := postgres.Open(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	p := &fakeProvider{}
	return env{db: db, conn: pgtest.Conn(t, url), provider: p, sources: sources.New(db, cmdb.Providers{fake: p})}
}

func (e env) addSource(t *testing.T) inventory.CMDBSource {
	t.Helper()
	src, err := e.sources.Add(context.Background(), newCustomer(), fake, json.RawMessage(`{"url": "http://cmdb"}`))
	if err != nil {
		t.Fatal(err)
	}
	return src
}

var errReadOnly = errors.New("read only")

// assets reads the stored Assets through the interface a Sync uses, then
// aborts so nothing is written.
func (e env) assets(t *testing.T, src inventory.CMDBSourceID) []*inventory.Asset {
	t.Helper()
	var got []*inventory.Asset
	_, err := e.db.CommitSync(context.Background(), src, time.Now(), func(existing []*inventory.Asset) (inventory.Reconciliation, error) {
		got = existing
		return inventory.Reconciliation{}, errReadOnly
	})
	if !errors.Is(err, errReadOnly) {
		t.Fatal(err)
	}
	return got
}

func (e env) queryInt(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.conn.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func newCustomer() inventory.CustomerID { return inventory.CustomerID(uuid.New()) }

func record(t *testing.T, id, name string) inventory.Record {
	t.Helper()
	imported, err := inventory.NewImportedAsset(inventory.ImportedAssetParams{Name: name, Kind: inventory.VirtualMachine})
	if err != nil {
		t.Fatal(err)
	}
	return inventory.Record{RecordID: id, Imported: imported}
}
