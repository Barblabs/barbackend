package sources_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"barbackend/internal/cmdb/cmdbtest"
	"barbackend/internal/encryption"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/sources"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	fake             = cmdbtest.Name
	validSettings    = cmdbtest.Settings
	validCredentials = cmdbtest.Credentials
)

type env struct {
	db       *postgres.DB
	conn     *pgx.Conn
	provider *cmdbtest.Provider
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
	p := &cmdbtest.Provider{}
	return env{db: db, conn: pgtest.Conn(t, url), provider: p, sources: sources.New(db, p.Providers(), newKey(t))}
}

func (e env) withKey(key encryption.Key) *sources.Service {
	return sources.New(e.db, e.provider.Providers(), key)
}

func newKey(t *testing.T) encryption.Key {
	t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	key, err := encryption.ParseKey(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func (e env) addSource(t *testing.T) inventory.CMDBSource {
	t.Helper()
	src, err := e.sources.Add(context.Background(), newCustomer(), fake, json.RawMessage(validSettings), json.RawMessage(validCredentials))
	if err != nil {
		t.Fatal(err)
	}
	return src
}

var errReadOnly = errors.New("read only")

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
