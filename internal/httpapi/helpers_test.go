package httpapi_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"barbackend/internal/cmdb"
	"barbackend/internal/cmdb/provider/providertest"
	"barbackend/internal/cognito/cognitotest"
	"barbackend/internal/encryption"
	"barbackend/internal/httpapi"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/tenancy"
	"barbackend/internal/users"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const allowedOrigin = "http://localhost:5173"

var operations = []struct{ method, path string }{
	{http.MethodGet, "/cmdb/source"},
	{http.MethodPost, "/cmdb/source"},
	{http.MethodPut, "/cmdb/source"},
	{http.MethodDelete, "/cmdb/source"},
	{http.MethodPost, "/cmdb/source/test"},
	{http.MethodPost, "/cmdb/source/sync"},
	{http.MethodGet, "/assets"},
}

// platformOperations are those only a Platform Admin may call.
var platformOperations = []struct{ method, path string }{
	{http.MethodPost, "/customers"},
	{http.MethodGet, "/customers"},
	{http.MethodPatch, "/customers/" + uuid.Nil.String()},
	{http.MethodPost, "/customers/" + uuid.Nil.String() + "/deactivate"},
	{http.MethodPost, "/customers/" + uuid.Nil.String() + "/reactivate"},
}

// customerAdminOperations are those only a Customer Admin may call.
var customerAdminOperations = []struct{ method, path string }{
	{http.MethodGet, "/users"},
	{http.MethodPost, "/users"},
	{http.MethodPatch, "/users/" + uuid.Nil.String()},
	{http.MethodPost, "/users/" + uuid.Nil.String() + "/disable"},
}

type env struct {
	db       *postgres.DB
	conn     *pgx.Conn
	pool     *cognitotest.Pool
	customer tenancy.CustomerID
	// token signs in a Viewer of customer.
	token    string
	provider *providertest.Provider
	admin    *fakeAdmin
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
	pool := cognitotest.New(t)
	svc := cmdb.New(db, p.Providers(), newKey(t), context.Background(), time.Minute)
	admin := &fakeAdmin{}
	router := httpapi.New(httpapi.Config{CMDB: svc, Users: users.New(db, pool.Verifier(t), admin), AllowedOrigins: []string{allowedOrigin}})
	e := env{db: db, conn: pgtest.Conn(t, url), pool: pool, provider: p, admin: admin, cmdb: svc, router: router}
	e.customer = e.newCustomer(t)
	e.token = e.signIn(t, e.newUser(t, tenancy.Viewer, e.customer))
	return e
}

func (e env) newCustomer(t *testing.T) tenancy.CustomerID {
	t.Helper()
	id := uuid.New()
	if _, err := e.conn.Exec(context.Background(), "INSERT INTO customers (id, name) VALUES ($1, $2)", id, id.String()); err != nil {
		t.Fatal(err)
	}
	return tenancy.CustomerID(id)
}

// newUser stores a User and returns their Cognito sub.
func (e env) newUser(t *testing.T, role tenancy.Role, customer tenancy.CustomerID) string {
	t.Helper()
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), uuid.NewString()+"@example.com", role, customer)
	if err != nil {
		t.Fatal(err)
	}
	sub := uuid.NewString()
	if err := e.db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.CreateUser(context.Background(), u, sub)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return sub
}

// fakeAdmin is a user pool that invites every email under a new sub.
type fakeAdmin struct {
	mu      sync.Mutex
	created []string
}

func (a *fakeAdmin) CreateUser(context.Context, string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sub := uuid.NewString()
	a.created = append(a.created, sub)
	return sub, nil
}

func (*fakeAdmin) DeleteUser(context.Context, string) error { return nil }

func (*fakeAdmin) DisableUser(context.Context, string) error { return nil }

func (a *fakeAdmin) invited() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.created)
}

func (e env) signIn(t *testing.T, sub string) string {
	t.Helper()
	return e.pool.AccessToken(t, sub)
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

// connect connects a CMDB Source for customer, running its first Sync.
func (e env) connect(t *testing.T, customer tenancy.CustomerID) inventory.CMDBSourceID {
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

// do sends req as the env's Viewer unless it carries its own Authorization.
func (e env) do(req *http.Request) *httptest.ResponseRecorder {
	if req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+e.token)
	}
	return e.send(req)
}

func (e env) send(req *http.Request) *httptest.ResponseRecorder {
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
