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
	customer inventory.CustomerID
	provider *cmdbtest.Provider
	sources  *sources.Service
	router   http.Handler
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
	router := httpapi.New(httpapi.Config{Sources: svc, Customer: customer, AllowedOrigins: []string{allowedOrigin}})
	return env{customer: customer, provider: p, sources: svc, router: router}
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

func (e env) testCredentials(login map[string]string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(login)
	return e.do(httptest.NewRequest(http.MethodPost, "/cmdb/source/test", strings.NewReader(string(body))))
}
