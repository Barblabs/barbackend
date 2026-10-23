package httpapi_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"barbackend/internal/cmdb"
	"barbackend/internal/inventory"
)

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

	_, body := e.getCMDBSource(t)

	want := `{"provider":"fake","url":"http://cmdb","user":"admin","lastSync":null,"lastSyncFailure":null}`
	if body != want {
		t.Errorf("body = %s, want %s", body, want)
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

func TestTestCMDBSourceCredentials(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		checkErr error
		want     string
	}{
		{
			name: "accepted",
			want: `{"ok":true}`,
		},
		{
			name:     "rejected",
			checkErr: &cmdb.Failure{Code: cmdb.InvalidCredentials, Message: "the cmdb rejected the user or password"},
			want:     `{"ok":false,"code":"invalid_credentials","error":"the cmdb rejected the user or password"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.provider.CheckErr = tt.checkErr

			rec := e.testCredentials(validLogin())

			if rec.Code != http.StatusOK || rec.Body.String() != tt.want {
				t.Errorf("response = %d %s, want 200 %s", rec.Code, rec.Body, tt.want)
			}
			if e.provider.Secret != validLogin()["password"] {
				t.Errorf("the provider checked secret %q, want the password sent", e.provider.Secret)
			}
			if _, body := e.getCMDBSource(t); body != "null" {
				t.Errorf("after a test: GET /cmdb/source = %s, want null since nothing is stored", body)
			}
		})
	}
}

func TestTestCMDBSourceCredentialsRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		edit func(map[string]string)
	}{
		{"missing provider", func(l map[string]string) { delete(l, "provider") }},
		{"unknown provider", func(l map[string]string) { l["provider"] = "servicenow" }},
		{"missing url", func(l map[string]string) { delete(l, "url") }},
		{"malformed url", func(l map[string]string) { l["url"] = "cmdb.example.com" }},
		{"missing user", func(l map[string]string) { delete(l, "user") }},
		{"missing password", func(l map[string]string) { delete(l, "password") }},
	}
	e := newEnv(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			login := validLogin()
			tt.edit(login)

			rec := e.testCredentials(login)

			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error":`) {
				t.Errorf("response = %d %s, want 400 with an error", rec.Code, rec.Body)
			}
		})
	}
}

func TestTestCMDBSourceCredentialsHidesInternalErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.CheckErr = errors.New("check broke")

	rec := e.testCredentials(validLogin())

	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "check broke") {
		t.Errorf("response = %d %s, want 500 without the cause", rec.Code, rec.Body)
	}
}

func TestTestCMDBSourceCredentialsRejectsMalformedJSON(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	rec := e.do(httptest.NewRequest(http.MethodPost, "/cmdb/source/test", strings.NewReader(`{"provider":`)))

	if rec.Code != http.StatusBadRequest {
		t.Errorf("response = %d %s, want 400", rec.Code, rec.Body)
	}
}

func TestSyncCMDBSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.addSource(t, e.customer)
	e.provider.Snapshot = inventory.Snapshot{
		Records: []inventory.Record{record(t, "a", "vm-a"), record(t, "b", "vm-b")},
		Skipped: []inventory.SkippedRecord{{RecordID: "c", Reason: "no name"}},
	}

	rec := e.sync(context.Background())

	got := decode[syncResult](t, rec, http.StatusOK)
	counts := got
	counts.LastSync = nil
	if want := (syncResult{Created: 2, Skipped: 1}); counts != want {
		t.Errorf("body = %s, want counts %+v", rec.Body, want)
	}
	if src, body := e.getCMDBSource(t); got.LastSync == nil || src.LastSync == nil || !got.LastSync.Equal(src.LastSync.Truncate(time.Microsecond)) {
		t.Errorf("lastSync = %v, want GET /cmdb/source's %s", got.LastSync, body)
	}
}

func TestSyncCMDBSourceWithoutConnectedSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.addSource(t, newCustomer())

	rec := e.sync(context.Background())

	if rec.Code != http.StatusNotFound {
		t.Errorf("response = %d %s, want 404", rec.Code, rec.Body)
	}
}

func TestSyncCMDBSourceFailure(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		err      error
		wantCode string
	}{
		{"classified by the provider", &cmdb.Failure{Code: cmdb.Unreachable, Message: "cmdb unreachable"}, "unreachable"},
		{"unclassified", errors.New("cmdb unreachable"), "sync_failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.addSource(t, e.customer)
			e.provider.Err = tt.err

			rec := e.sync(context.Background())

			got := decode[syncFailure](t, rec, http.StatusBadGateway)
			if got.Code != tt.wantCode || !strings.Contains(got.Error, "cmdb unreachable") {
				t.Errorf("body = %s, want code %q and the cause", rec.Body, tt.wantCode)
			}
			if src, body := e.getCMDBSource(t); src.LastSyncFailure == nil || !strings.Contains(src.LastSyncFailure.Error, "cmdb unreachable") {
				t.Errorf("GET /cmdb/source = %s, want the failed Sync Run", body)
			}
		})
	}
}

func TestSyncCMDBSourceWhileAnotherSyncRuns(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addSource(t, e.customer)
	release := e.holdSyncLock(t, src.ID())

	rec := e.sync(context.Background())
	release()

	got := decode[syncFailure](t, rec, http.StatusConflict)
	if got.Code != "sync_in_progress" {
		t.Errorf("body = %s, want code sync_in_progress", rec.Body)
	}
	if src, body := e.getCMDBSource(t); src.LastSyncFailure != nil {
		t.Errorf("GET /cmdb/source = %s, want no failure, since the running Sync succeeded", body)
	}
}

func TestSyncCMDBSourceOutlivesItsRequest(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.addSource(t, e.customer)
	closedTab, cancel := context.WithCancel(context.Background())
	cancel()

	rec := e.sync(closedTab)

	got := decode[syncResult](t, rec, http.StatusOK)
	if src, body := e.getCMDBSource(t); src.LastSync == nil || !got.LastSync.Equal(src.LastSync.Truncate(time.Microsecond)) {
		t.Errorf("GET /cmdb/source = %s, want the Sync that finished at %v", body, got.LastSync)
	}
}

func TestSyncCMDBSourceExceedingTheTimeLimitFails(t *testing.T) {
	t.Parallel()
	e := newEnv(t).withSyncContext(context.Background(), 50*time.Millisecond)
	e.addSource(t, e.customer)
	e.provider.Hanging = make(chan struct{})

	rec := e.sync(context.Background())

	got := decode[syncFailure](t, rec, http.StatusBadGateway)
	if !strings.Contains(got.Error, context.DeadlineExceeded.Error()) {
		t.Errorf("body = %s, want the deadline", rec.Body)
	}
	if src, body := e.getCMDBSource(t); src.LastSyncFailure == nil {
		t.Errorf("GET /cmdb/source = %s, want the failed Sync Run", body)
	}
}

func TestSyncCMDBSourceCanceledByShutdownFails(t *testing.T) {
	t.Parallel()
	lifetime, shutdown := context.WithCancel(context.Background())
	e := newEnv(t).withSyncContext(lifetime, time.Minute)
	e.addSource(t, e.customer)
	e.provider.Hanging = make(chan struct{})
	go func() {
		<-e.provider.Hanging
		shutdown()
	}()

	rec := e.sync(context.Background())

	got := decode[syncFailure](t, rec, http.StatusBadGateway)
	if !strings.Contains(got.Error, context.Canceled.Error()) {
		t.Errorf("body = %s, want the cancellation", rec.Body)
	}
	if src, body := e.getCMDBSource(t); src.LastSyncFailure == nil {
		t.Errorf("GET /cmdb/source = %s, want the failed Sync Run", body)
	}
}
