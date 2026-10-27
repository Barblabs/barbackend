package cmdb_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"barbackend/internal/cmdb"
	"barbackend/internal/cmdb/provider/providertest"
	"barbackend/internal/encryption"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type env struct {
	db       *postgres.DB
	conn     *pgx.Conn
	provider *providertest.Provider
	key      encryption.Key
	cmdb     *cmdb.Service
}

func newEnv(t *testing.T) env {
	t.Helper()
	url := pgtest.URL(t)
	db, err := postgres.Open(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	e := env{db: db, conn: pgtest.Conn(t, url), provider: &providertest.Provider{}, key: newKey(t)}
	e.cmdb = e.withSyncLimits(context.Background(), time.Minute)
	return e
}

func (e env) withKey(key encryption.Key) *cmdb.Service {
	return cmdb.New(e.db, e.provider.Providers(), key, context.Background(), time.Minute)
}

func (e env) withSyncLimits(lifetime context.Context, timeout time.Duration) *cmdb.Service {
	return cmdb.New(e.db, e.provider.Providers(), e.key, lifetime, timeout)
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

// connect connects a CMDB Source for a new Customer, running its first Sync.
func (e env) connect(t *testing.T) (tenancy.CustomerID, inventory.CMDBSourceID) {
	t.Helper()
	customer := newCustomer()
	if _, err := e.cmdb.Connect(context.Background(), customer, providertest.Name, providertest.Login); err != nil {
		t.Fatal(err)
	}
	return customer, e.connected(t, customer).Source.ID()
}

func (e env) connected(t *testing.T, customer tenancy.CustomerID) postgres.StoredCMDBSource {
	t.Helper()
	var stored postgres.StoredCMDBSource
	if err := e.db.InTx(context.Background(), func(tx *postgres.Tx) (err error) {
		stored, err = tx.ConnectedCMDBSource(context.Background(), customer)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return stored
}

func (e env) connectedSource(t *testing.T, customer tenancy.CustomerID) cmdb.ConnectedSource {
	t.Helper()
	src, err := e.cmdb.ConnectedSource(context.Background(), customer)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func (e env) holdSyncLock(t *testing.T, src inventory.CMDBSourceID) (release func()) {
	t.Helper()
	locked, unlock, done := make(chan struct{}), make(chan struct{}), make(chan error)
	go func() {
		_, err := e.db.CommitSync(context.Background(), src, time.Now(), func(existing []*inventory.Asset) (inventory.Reconciliation, error) {
			close(locked)
			<-unlock
			return inventory.Reconcile(src, existing, inventory.Snapshot{})
		})
		done <- err
	}()
	<-locked
	return func() {
		close(unlock)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func (e env) rows(t *testing.T, query string, args ...any) [][]string {
	t.Helper()
	rows, err := e.conn.Query(context.Background(), query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got [][]string
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			t.Fatal(err)
		}
		row := make([]string, len(values))
		for i, v := range values {
			row[i] = fmt.Sprint(v)
		}
		got = append(got, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return got
}

func (e env) failedRuns(t *testing.T) int {
	t.Helper()
	return e.queryInt(t, "SELECT count(*) FROM sync_runs WHERE outcome_id = $1", int16(inventory.SyncFailed))
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

func newCustomer() tenancy.CustomerID { return tenancy.CustomerID(uuid.New()) }

func record(t *testing.T, id, name string) inventory.Record {
	t.Helper()
	imported, err := inventory.NewImportedAsset(inventory.ImportedAssetParams{Name: name, Kind: inventory.VirtualMachine})
	if err != nil {
		t.Fatal(err)
	}
	return inventory.Record{RecordID: id, Imported: imported}
}
