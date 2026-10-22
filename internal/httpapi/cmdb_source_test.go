package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"barbackend/internal/cmdb/cmdbtest"
	"barbackend/internal/inventory"
)

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

func TestGetCMDBSourceWithoutConnectedSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.addSource(t, newCustomer())

	rec := e.do(httptest.NewRequest(http.MethodGet, "/cmdb/source", nil))

	if rec.Code != http.StatusOK || rec.Body.String() != "null" {
		t.Errorf("response = %d %s, want 200 null", rec.Code, rec.Body)
	}
}

func TestGetCMDBSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.addSource(t, e.customer)

	got, body := e.getCMDBSource(t)

	want := `{"provider":"fake","url":"http://cmdb","user":"admin","lastSync":null,"lastSyncFailure":null}`
	if body != want {
		t.Errorf("body = %s, want %s", body, want)
	}
	if strings.Contains(body, cmdbtest.Secret) || got.Provider != string(cmdbtest.Name) {
		t.Errorf("body = %s, want the fake source without its secret", body)
	}
}

func TestGetCMDBSourceReportsLatestSyncRuns(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addSource(t, e.customer)
	e.provider.Snapshot = inventory.Snapshot{}

	succeeded, err := e.sources.Sync(context.Background(), src.ID())
	if err != nil {
		t.Fatal(err)
	}
	got, body := e.getCMDBSource(t)
	if got.LastSync == nil || !got.LastSync.Equal(succeeded.Finished().Truncate(time.Microsecond)) || got.LastSyncFailure != nil {
		t.Errorf("after a successful Sync: body = %s, want lastSync %v and no failure", body, succeeded.Finished())
	}

	e.provider.Err = errors.New("cmdb unreachable")
	beforeFailure := time.Now()
	if _, err := e.sources.Sync(context.Background(), src.ID()); err == nil {
		t.Fatal("Sync succeeded, want a failure")
	}
	got, body = e.getCMDBSource(t)
	if got.LastSync == nil || !got.LastSync.Equal(succeeded.Finished().Truncate(time.Microsecond)) {
		t.Errorf("after a failed Sync: body = %s, want lastSync still %v", body, succeeded.Finished())
	}
	if f := got.LastSyncFailure; f == nil || f.At.Before(beforeFailure.Truncate(time.Microsecond)) || !strings.Contains(f.Error, "cmdb unreachable") {
		t.Errorf("after a failed Sync: body = %s, want the failure", body)
	}

	e.provider.Err = nil
	if _, err := e.sources.Sync(context.Background(), src.ID()); err != nil {
		t.Fatal(err)
	}
	if got, body = e.getCMDBSource(t); got.LastSyncFailure != nil {
		t.Errorf("after a later successful Sync: body = %s, want no failure", body)
	}
}

func TestGetCMDBSourceWithOnlyFailedSyncs(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addSource(t, e.customer)
	e.provider.Err = errors.New("cmdb unreachable")
	if _, err := e.sources.Sync(context.Background(), src.ID()); err == nil {
		t.Fatal("Sync succeeded, want a failure")
	}

	if got, body := e.getCMDBSource(t); got.LastSync != nil || got.LastSyncFailure == nil {
		t.Errorf("body = %s, want no lastSync and a failure", body)
	}
}
