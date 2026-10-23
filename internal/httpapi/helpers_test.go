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

	"barbackend/internal/cmdb/cmdbtest"
	"barbackend/internal/encryption"
	"barbackend/internal/httpapi"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/sources"
	"github.com/google/uuid"
)

const allowedOrigin = "http://localhost:5173"

// env is a router wired as serve wires it, on its own database, acting for
// customer.
type env struct {
	db       *postgres.DB
	customer inventory.CustomerID
	provider *cmdbtest.Provider
	sources  *sources.Service
	router   http.Handler
}

func (e env) withSyncContext(lifetime context.Context, timeout time.Duration) env {
	e.router = newRouter(e.sources, e.customer, lifetime, timeout)
	return e
}

func newRouter(svc *sources.Service, customer inventory.CustomerID, lifetime context.Context, syncTimeout time.Duration) http.Handler {
	return httpapi.New(httpapi.Config{
		Sources:        svc,
		Customer:       customer,
		AllowedOrigins: []string{allowedOrigin},
		Lifetime:       lifetime,
		SyncTimeout:    syncTimeout,
	})
}

func newEnv(t *testing.T) env {
	t.Helper()
	db, err := postgres.Open(context.Background(), pgtest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	p := &cmdbtest.Provider{}
	svc := sources.New(db, p.Providers(), newKey(t))
	customer := newCustomer()
	router := newRouter(svc, customer, context.Background(), time.Minute)
	return env{db: db, customer: customer, provider: p, sources: svc, router: router}
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

// addSource adds a CMDB Source for customer as the CLI does.
func (e env) addSource(t *testing.T, customer inventory.CustomerID) inventory.CMDBSource {
	t.Helper()
	src, err := e.sources.Add(context.Background(), customer, cmdbtest.Name, json.RawMessage(cmdbtest.Settings), json.RawMessage(cmdbtest.Credentials))
	if err != nil {
		t.Fatal(err)
	}
	return src
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

// validLogin is a request body for the fake CMDB Provider; each call returns a
// fresh map, so tests can edit it.
func validLogin() map[string]string {
	return map[string]string{"provider": string(cmdbtest.Name), "url": "http://cmdb", "user": "admin", "password": cmdbtest.Secret}
}

func (e env) postLogin(path string, login map[string]string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(login)
	return e.do(httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body))))
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

// sync runs a Sync of the Connected CMDB Source with a request bound to ctx.
func (e env) sync(ctx context.Context) *httptest.ResponseRecorder {
	return e.do(httptest.NewRequestWithContext(ctx, http.MethodPost, "/cmdb/source/sync", nil))
}

// decode fails t unless rec has status want and a body of type T.
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

// holdSyncLock holds the lock a Sync of src commits under, as a running Sync
// does, until the returned func releases it.
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
