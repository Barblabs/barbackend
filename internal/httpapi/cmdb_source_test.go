package httpapi_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"barbackend/internal/cmdb"
	"barbackend/internal/cmdb/cmdbtest"
	"barbackend/internal/inventory"
	"barbackend/internal/sources"
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

			rec := e.postLogin("/cmdb/source/test", validLogin())

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

// loginEndpoints take a login as their body, so they reject the same
// invalid requests.
var loginEndpoints = []struct{ method, path string }{
	{http.MethodPost, "/cmdb/source/test"},
	{http.MethodPost, "/cmdb/source"},
	{http.MethodPut, "/cmdb/source"},
}

func TestLoginEndpointsRejectInvalidRequests(t *testing.T) {
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
	// Connected, so updating finds a source to check the login for.
	e.addSource(t, e.customer)
	for _, ep := range loginEndpoints {
		for _, tt := range tests {
			t.Run(ep.method+" "+ep.path+" "+tt.name, func(t *testing.T) {
				t.Parallel()
				login := validLogin()
				tt.edit(login)

				rec := e.sendLogin(ep.method, ep.path, login)

				if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error":`) {
					t.Errorf("response = %d %s, want 400 with an error", rec.Code, rec.Body)
				}
			})
		}
	}
}

func TestTestCMDBSourceCredentialsHidesInternalErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.CheckErr = errors.New("check broke")

	rec := e.postLogin("/cmdb/source/test", validLogin())

	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "check broke") {
		t.Errorf("response = %d %s, want 500 without the cause", rec.Code, rec.Body)
	}
}

func TestLoginEndpointsRejectMalformedJSON(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, ep := range loginEndpoints {
		rec := e.do(httptest.NewRequest(ep.method, ep.path, strings.NewReader(`{"provider":`)))

		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s %s: response = %d %s, want 400", ep.method, ep.path, rec.Code, rec.Body)
		}
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

			got := decode[codedError](t, rec, http.StatusBadGateway)
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

	got := decode[codedError](t, rec, http.StatusConflict)
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

	got := decode[codedError](t, rec, http.StatusBadGateway)
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

	got := decode[codedError](t, rec, http.StatusBadGateway)
	if !strings.Contains(got.Error, context.Canceled.Error()) {
		t.Errorf("body = %s, want the cancellation", rec.Body)
	}
	if src, body := e.getCMDBSource(t); src.LastSyncFailure == nil {
		t.Errorf("GET /cmdb/source = %s, want the failed Sync Run", body)
	}
}

func TestConnectCMDBSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "a", "vm-a")}}

	rec := e.postLogin("/cmdb/source", validLogin())

	got := decode[cmdbSource](t, rec, http.StatusOK)
	if got.Provider != "fake" || got.URL != "http://cmdb" || got.User != "admin" || got.LastSync == nil || got.LastSyncFailure != nil {
		t.Errorf("body = %s, want the source with a lastSync and no failure", rec.Body)
	}
	if _, body := e.getCMDBSource(t); body != rec.Body.String() {
		t.Errorf("GET /cmdb/source = %s, want the connect response %s", body, rec.Body)
	}
	if run := decode[syncResult](t, e.sync(context.Background()), http.StatusOK); run.Created != 0 || run.Updated != 0 {
		t.Errorf("a later Sync = %+v, want nothing to create or update since the first Sync imported the Asset", run)
	}
}

func TestConnectCMDBSourceWithRejectedCredentials(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.CheckErr = &cmdb.Failure{Code: cmdb.InvalidCredentials, Message: "the cmdb rejected the user or password"}

	rec := e.postLogin("/cmdb/source", validLogin())

	if want := `{"code":"invalid_credentials","error":"the cmdb rejected the user or password"}`; rec.Code != http.StatusUnprocessableEntity || rec.Body.String() != want {
		t.Errorf("response = %d %s, want 422 %s", rec.Code, rec.Body, want)
	}
	if _, body := e.getCMDBSource(t); body != "null" {
		t.Errorf("GET /cmdb/source = %s, want null since nothing is stored", body)
	}
}

func TestConnectCMDBSourceWithFailedFirstSync(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Err = errors.New("cmdb unreachable")

	rec := e.postLogin("/cmdb/source", validLogin())

	got := decode[cmdbSource](t, rec, http.StatusOK)
	if got.LastSync != nil || got.LastSyncFailure == nil || !strings.Contains(got.LastSyncFailure.Error, "cmdb unreachable") {
		t.Errorf("body = %s, want no lastSync and the failure", rec.Body)
	}
	e.provider.Err = nil
	if rec := e.sync(context.Background()); rec.Code != http.StatusOK {
		t.Errorf("a later Sync = %d %s, want 200 since the source stays connected", rec.Code, rec.Body)
	}
}

func TestConnectCMDBSourceWhenAlreadyConnected(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.addSource(t, e.customer)
	login := validLogin()
	login["url"] = "http://other-cmdb"

	rec := e.postLogin("/cmdb/source", login)

	got := decode[codedError](t, rec, http.StatusConflict)
	if got.Code != "already_connected" {
		t.Errorf("body = %s, want code already_connected", rec.Body)
	}
	if src, body := e.getCMDBSource(t); src.URL != "http://cmdb" {
		t.Errorf("GET /cmdb/source = %s, want the source connected first", body)
	}
}

func TestConnectCMDBSourceStoresSealedCredentials(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	decode[cmdbSource](t, e.postLogin("/cmdb/source", validLogin()), http.StatusOK)

	stored := e.connected(t)
	if len(stored.Credentials) == 0 || bytes.Contains(stored.Credentials, []byte(cmdbtest.Secret)) {
		t.Errorf("stored credentials = %q, want ciphertext without the password", stored.Credentials)
	}
	if e.provider.Secret != cmdbtest.Secret {
		t.Errorf("the first Sync used secret %q, want the password sent", e.provider.Secret)
	}
}

func TestConnectCMDBSourceWithFirstSyncExceedingTheTimeLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t).withSyncContext(context.Background(), 50*time.Millisecond)
	e.provider.Hanging = make(chan struct{})

	rec := e.postLogin("/cmdb/source", validLogin())

	got := decode[cmdbSource](t, rec, http.StatusOK)
	if got.LastSync != nil || got.LastSyncFailure == nil || !strings.Contains(got.LastSyncFailure.Error, context.DeadlineExceeded.Error()) {
		t.Errorf("body = %s, want no lastSync and the deadline as the failure", rec.Body)
	}
}

// rotatedLogin is validLogin with every field but the provider changed.
func rotatedLogin() map[string]string {
	return map[string]string{"provider": string(cmdbtest.Name), "url": "http://new-cmdb", "user": "new-admin", "password": "new-secret"}
}

func TestUpdateCMDBSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addSource(t, e.customer)
	synced := decode[syncResult](t, e.sync(context.Background()), http.StatusOK)

	rec := e.sendLogin(http.MethodPut, "/cmdb/source", rotatedLogin())

	got := decode[cmdbSource](t, rec, http.StatusOK)
	if got.URL != "http://new-cmdb" || got.User != "new-admin" {
		t.Errorf("body = %s, want the new url and user", rec.Body)
	}
	if got.LastSync == nil || !got.LastSync.Equal(synced.LastSync.Truncate(time.Microsecond)) {
		t.Errorf("body = %s, want lastSync still %v, since the Sync history stays and the update runs no Sync", rec.Body, synced.LastSync)
	}
	if _, body := e.getCMDBSource(t); body != rec.Body.String() {
		t.Errorf("GET /cmdb/source = %s, want the update response %s", body, rec.Body)
	}
	if id := e.connected(t).Source.ID(); id != src.ID() {
		t.Errorf("connected source = %s, want the same source %s", id, src.ID())
	}
	if rec := e.sync(context.Background()); rec.Code != http.StatusOK || e.provider.Secret != "new-secret" {
		t.Errorf("a later Sync = %d %s with secret %q, want 200 with the new password", rec.Code, rec.Body, e.provider.Secret)
	}
}

func TestUpdateCMDBSourceWithRejectedCredentials(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.addSource(t, e.customer)
	before := e.connected(t)
	e.provider.CheckErr = &cmdb.Failure{Code: cmdb.InvalidCredentials, Message: "the cmdb rejected the user or password"}

	rec := e.sendLogin(http.MethodPut, "/cmdb/source", rotatedLogin())

	if want := `{"code":"invalid_credentials","error":"the cmdb rejected the user or password"}`; rec.Code != http.StatusUnprocessableEntity || rec.Body.String() != want {
		t.Errorf("response = %d %s, want 422 %s", rec.Code, rec.Body, want)
	}
	if after := e.connected(t); !bytes.Equal(after.Settings, before.Settings) || !bytes.Equal(after.Credentials, before.Credentials) {
		t.Errorf("stored source = %s %x, want unchanged %s %x", after.Settings, after.Credentials, before.Settings, before.Credentials)
	}
}

func TestUpdateCMDBSourceWithoutConnectedSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.addSource(t, newCustomer())

	rec := e.sendLogin(http.MethodPut, "/cmdb/source", rotatedLogin())

	if rec.Code != http.StatusNotFound {
		t.Errorf("response = %d %s, want 404", rec.Code, rec.Body)
	}
}

func TestUpdateCMDBSourceKeepsAssetsAndDeclarations(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.addSource(t, e.customer)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "a", "vm-a")}}
	decode[syncResult](t, e.sync(context.Background()), http.StatusOK)
	if _, err := e.conn.Exec(context.Background(), "UPDATE assets SET declared_exposure_id = $1", int16(inventory.Internal)); err != nil {
		t.Fatal(err)
	}
	assets := func() [][]string {
		return e.rows(t, "SELECT record_id, name, declared_exposure_id FROM assets WHERE cmdb_source_id = $1 ORDER BY record_id", e.connected(t).Source.ID().String())
	}
	before := assets()

	decode[cmdbSource](t, e.sendLogin(http.MethodPut, "/cmdb/source", rotatedLogin()), http.StatusOK)

	if after := assets(); !reflect.DeepEqual(after, before) {
		t.Errorf("assets = %v, want unchanged %v", after, before)
	}
}

func (e env) disconnect() *httptest.ResponseRecorder {
	return e.do(httptest.NewRequest(http.MethodDelete, "/cmdb/source", nil))
}

func TestDisconnectCMDBSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addSource(t, e.customer)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "a", "vm-a"), record(t, "b", "vm-b")}}
	decode[syncResult](t, e.sync(context.Background()), http.StatusOK)

	rec := e.disconnect()

	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Errorf("response = %d %s, want 204 with no body", rec.Code, rec.Body)
	}
	if rec := e.do(httptest.NewRequest(http.MethodGet, "/cmdb/source", nil)); rec.Body.String() != "null" {
		t.Errorf("GET /cmdb/source = %s, want null", rec.Body)
	}
	if got := e.rows(t, "SELECT record_id, inactive_since IS NOT NULL FROM assets WHERE cmdb_source_id = $1 ORDER BY record_id", src.ID().String()); !reflect.DeepEqual(got, [][]string{{"a", "true"}, {"b", "true"}}) {
		t.Errorf("assets = %v, want a and b stored and Inactive", got)
	}
	if got := e.rows(t, "SELECT disconnected_at IS NOT NULL FROM cmdb_sources WHERE id = $1", src.ID().String()); !reflect.DeepEqual(got, [][]string{{"true"}}) {
		t.Errorf("cmdb source = %v, want it stored and disconnected", got)
	}
}

func TestDisconnectCMDBSourceWithoutConnectedSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.addSource(t, newCustomer())

	rec := e.disconnect()

	if rec.Code != http.StatusNotFound {
		t.Errorf("response = %d %s, want 404", rec.Code, rec.Body)
	}
}

func TestDisconnectCMDBSourceWhileASyncRuns(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addSource(t, e.customer)
	release := e.holdSyncLock(t, src.ID())

	rec := e.disconnect()
	release()

	got := decode[codedError](t, rec, http.StatusConflict)
	if got.Code != "sync_in_progress" {
		t.Errorf("body = %s, want code sync_in_progress", rec.Body)
	}
	if id := e.connected(t).Source.ID(); id != src.ID() {
		t.Errorf("connected source = %s, want %s still connected", id, src.ID())
	}
}

func TestSyncOfDisconnectedCMDBSourceFails(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addSource(t, e.customer)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "a", "vm-a")}}
	decode[syncResult](t, e.sync(context.Background()), http.StatusOK)
	if rec := e.disconnect(); rec.Code != http.StatusNoContent {
		t.Fatalf("disconnect = %d %s, want 204", rec.Code, rec.Body)
	}
	stored := func() [][]string {
		return e.rows(t, `SELECT 'asset', record_id, name, inactive_since::text FROM assets WHERE cmdb_source_id = $1
			UNION ALL SELECT 'run', id::text, outcome_id::text, '' FROM sync_runs WHERE cmdb_source_id = $1
			ORDER BY 1, 2`, src.ID().String())
	}
	before := stored()
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "a", "renamed"), record(t, "b", "vm-b")}}

	_, err := e.sources.Sync(context.Background(), src.ID())

	if !errors.Is(err, sources.ErrDisconnected) {
		t.Errorf("err = %v, want ErrDisconnected", err)
	}
	if after := stored(); !reflect.DeepEqual(after, before) {
		t.Errorf("assets and sync runs = %v, want unchanged %v", after, before)
	}
	if rec := e.sync(context.Background()); rec.Code != http.StatusNotFound {
		t.Errorf("POST /cmdb/source/sync = %d %s, want 404", rec.Code, rec.Body)
	}
}

func TestConnectAfterDisconnectCreatesANewCMDBSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	old := e.addSource(t, e.customer)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "a", "vm-a")}}
	decode[syncResult](t, e.sync(context.Background()), http.StatusOK)
	if rec := e.disconnect(); rec.Code != http.StatusNoContent {
		t.Fatalf("disconnect = %d %s, want 204", rec.Code, rec.Body)
	}

	rec := e.postLogin("/cmdb/source", validLogin())

	decode[cmdbSource](t, rec, http.StatusOK)
	if id := e.connected(t).Source.ID(); id == old.ID() {
		t.Errorf("connected source = %s, want a new one", id)
	}
	if got := e.rows(t, "SELECT cmdb_source_id::text, record_id, inactive_since IS NOT NULL FROM assets ORDER BY inactive_since IS NOT NULL"); !reflect.DeepEqual(got, [][]string{
		{e.connected(t).Source.ID().String(), "a", "false"},
		{old.ID().String(), "a", "true"},
	}) {
		t.Errorf("assets = %v, want a new Active one and the old one still Inactive", got)
	}
}
