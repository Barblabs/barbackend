package httpapi_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"barbackend/internal/cmdb"
	"barbackend/internal/cmdb/provider/providertest"
	"barbackend/internal/encryption"
	"barbackend/internal/httpapi"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const allowedOrigin = "http://localhost:5173"

type env struct {
	db       *postgres.DB
	conn     *pgx.Conn
	customer inventory.CustomerID
	provider *providertest.Provider
	cmdb     *cmdb.Service
	router   http.Handler
}

func newEnv(t *testing.T) env {
	t.Helper()
	url := pgtest.URL(t)
	db, err := postgres.Open(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	p := &providertest.Provider{}
	svc := cmdb.New(db, p.Providers(), newKey(t), context.Background(), time.Minute)
	customer := newCustomer()
	router := httpapi.New(httpapi.Config{CMDB: svc, Customer: customer, AllowedOrigins: []string{allowedOrigin}})
	return env{db: db, conn: pgtest.Conn(t, url), customer: customer, provider: p, cmdb: svc, router: router}
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

func newCustomer() inventory.CustomerID { return inventory.CustomerID(uuid.New()) }

// connect connects a CMDB Source for customer, running its first Sync.
func (e env) connect(t *testing.T, customer inventory.CustomerID) inventory.CMDBSourceID {
	t.Helper()
	if _, err := e.cmdb.Connect(context.Background(), customer, providertest.Name, providertest.Login); err != nil {
		t.Fatal(err)
	}
	var stored postgres.StoredCMDBSource
	if err := e.db.InTx(context.Background(), func(tx *postgres.Tx) (err error) {
		stored, err = tx.ConnectedCMDBSource(context.Background(), customer)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return stored.Source.ID()
}

func (e env) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

type cmdbSource struct {
	Provider        string     `json:"provider"`
	URL             string     `json:"url"`
	User            string     `json:"user"`
	LastSync        *time.Time `json:"lastSync"`
	LastSyncFailure *struct {
		At    time.Time `json:"at"`
		Error string    `json:"error"`
	} `json:"lastSyncFailure"`
}

func (e env) getCMDBSource(t *testing.T) (cmdbSource, string) {
	t.Helper()
	rec := e.do(httptest.NewRequest(http.MethodGet, "/cmdb/source", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s, want 200", rec.Code, rec.Body)
	}
	var got cmdbSource
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got, rec.Body.String()
}

func validLogin() map[string]string {
	return map[string]string{"provider": string(providertest.Name), "url": "http://cmdb", "user": "admin", "password": providertest.Secret}
}

func (e env) postLogin(path string, login map[string]string) *httptest.ResponseRecorder {
	return e.sendLogin(http.MethodPost, path, login)
}

func (e env) sendLogin(method, path string, login map[string]string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(login)
	return e.do(httptest.NewRequest(method, path, strings.NewReader(string(body))))
}

type syncResult struct {
	LastSync    *time.Time `json:"lastSync"`
	Created     int        `json:"created"`
	Updated     int        `json:"updated"`
	Deactivated int        `json:"deactivated"`
	Reactivated int        `json:"reactivated"`
	Skipped     int        `json:"skipped"`
}

type codedError struct {
	Code  string `json:"code"`
	Error string `json:"error"`
}

func (e env) sync(ctx context.Context) *httptest.ResponseRecorder {
	return e.do(httptest.NewRequestWithContext(ctx, http.MethodPost, "/cmdb/source/sync", nil))
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder, want int) T {
	t.Helper()
	var got T
	if rec.Code != want {
		t.Fatalf("status = %d %s, want %d", rec.Code, rec.Body, want)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func record(t *testing.T, id, name string) inventory.Record {
	t.Helper()
	imported, err := inventory.NewImportedAsset(inventory.ImportedAssetParams{Name: name, Kind: inventory.VirtualMachine})
	if err != nil {
		t.Fatal(err)
	}
	return inventory.Record{RecordID: id, Imported: imported}
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
