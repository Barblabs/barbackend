package httpapi_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"barbackend/internal/cmdb"
	"barbackend/internal/inventory"
)

func TestGetCMDBSourceWithoutConnectedSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.connect(t, newCustomer())

	rec := e.do(httptest.NewRequest(http.MethodGet, "/cmdb/source", nil))

	if rec.Code != http.StatusOK || rec.Body.String() != "null" {
		t.Errorf("response = %d %s, want 200 null", rec.Code, rec.Body)
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
		})
	}
}

var loginEndpoints = []struct {
	method, path  string
	takesProvider bool
}{
	{http.MethodPost, "/cmdb/source/test", true},
	{http.MethodPost, "/cmdb/source", true},
	{http.MethodPut, "/cmdb/source", false},
}

func TestLoginEndpointsRejectInvalidRequests(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		edit          func(map[string]string)
		aboutProvider bool
		code          string
	}{
		{"missing provider", func(l map[string]string) { delete(l, "provider") }, true, "invalid_request"},
		{"unknown provider", func(l map[string]string) { l["provider"] = "servicenow" }, true, "invalid_login"},
		{"missing url", func(l map[string]string) { delete(l, "url") }, false, "invalid_request"},
		{"malformed url", func(l map[string]string) { l["url"] = "cmdb.example.com" }, false, "invalid_login"},
		{"missing user", func(l map[string]string) { delete(l, "user") }, false, "invalid_request"},
		{"missing password", func(l map[string]string) { delete(l, "password") }, false, "invalid_request"},
	}
	e := newEnv(t)
	e.connect(t, e.customer)
	for _, ep := range loginEndpoints {
		for _, tt := range tests {
			if tt.aboutProvider && !ep.takesProvider {
				continue
			}
			t.Run(ep.method+" "+ep.path+" "+tt.name, func(t *testing.T) {
				t.Parallel()
				login := validLogin()
				tt.edit(login)

				rec := e.sendLogin(ep.method, ep.path, login)

				if got := decode[codedError](t, rec, http.StatusBadRequest); got.Code != tt.code || got.Error == "" {
					t.Errorf("body = %s, want code %s with an error", rec.Body, tt.code)
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
	e.connect(t, e.customer)
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
	if src, body := e.getCMDBSource(t); got.LastSync == nil || src.LastSync == nil || !got.LastSync.Equal(*src.LastSync) {
		t.Errorf("lastSync = %v, want GET /cmdb/source's %s", got.LastSync, body)
	}
}

func TestSyncCMDBSourceWithoutConnectedSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.connect(t, newCustomer())

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
			e.connect(t, e.customer)
			e.provider.Err = tt.err

			rec := e.sync(context.Background())

			got := decode[codedError](t, rec, http.StatusBadGateway)
			if got.Code != tt.wantCode || !strings.Contains(got.Error, "cmdb unreachable") {
				t.Errorf("body = %s, want code %q and the cause", rec.Body, tt.wantCode)
			}
		})
	}
}

func TestSyncCMDBSourceWhileAnotherSyncRuns(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.connect(t, e.customer)
	release := e.holdSyncLock(t, src)

	rec := e.sync(context.Background())
	release()

	got := decode[codedError](t, rec, http.StatusConflict)
	if got.Code != "sync_in_progress" {
		t.Errorf("body = %s, want code sync_in_progress", rec.Body)
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
}

func TestConnectCMDBSourceWithRejectedCredentials(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.CheckErr = &cmdb.Failure{Code: cmdb.InvalidCredentials, Message: "the cmdb rejected the user or password"}

	rec := e.postLogin("/cmdb/source", validLogin())

	if want := `{"code":"invalid_credentials","error":"the cmdb rejected the user or password"}`; rec.Code != http.StatusUnprocessableEntity || rec.Body.String() != want {
		t.Errorf("response = %d %s, want 422 %s", rec.Code, rec.Body, want)
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
}

func TestConnectCMDBSourceWhenAlreadyConnected(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.connect(t, e.customer)
	login := validLogin()
	login["url"] = "http://other-cmdb"

	rec := e.postLogin("/cmdb/source", login)

	got := decode[codedError](t, rec, http.StatusConflict)
	if got.Code != "already_connected" {
		t.Errorf("body = %s, want code already_connected", rec.Body)
	}
}

func rotatedLogin() map[string]string {
	return map[string]string{"url": "http://new-cmdb", "user": "new-admin", "password": "new-secret"}
}

func TestUpdateCMDBSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.connect(t, e.customer)

	rec := e.sendLogin(http.MethodPut, "/cmdb/source", rotatedLogin())

	got := decode[cmdbSource](t, rec, http.StatusOK)
	if got.URL != "http://new-cmdb" || got.User != "new-admin" || got.LastSync == nil {
		t.Errorf("body = %s, want the new url and user, and the lastSync of the first Sync", rec.Body)
	}
	if _, body := e.getCMDBSource(t); body != rec.Body.String() {
		t.Errorf("GET /cmdb/source = %s, want the update response %s", body, rec.Body)
	}
	if e.provider.Secret != "new-secret" {
		t.Errorf("the provider checked secret %q, want the password sent", e.provider.Secret)
	}
}

func TestUpdateCMDBSourceWithoutConnectedSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.connect(t, newCustomer())

	rec := e.sendLogin(http.MethodPut, "/cmdb/source", rotatedLogin())

	if rec.Code != http.StatusNotFound {
		t.Errorf("response = %d %s, want 404", rec.Code, rec.Body)
	}
}

func (e env) disconnect() *httptest.ResponseRecorder {
	return e.do(httptest.NewRequest(http.MethodDelete, "/cmdb/source", nil))
}

func TestDisconnectCMDBSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.connect(t, e.customer)

	rec := e.disconnect()

	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Errorf("response = %d %s, want 204 with no body", rec.Code, rec.Body)
	}
	if _, body := e.getCMDBSource(t); body != "null" {
		t.Errorf("GET /cmdb/source = %s, want null", body)
	}
}

func TestDisconnectCMDBSourceWithoutConnectedSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.connect(t, newCustomer())

	rec := e.disconnect()

	if rec.Code != http.StatusNotFound {
		t.Errorf("response = %d %s, want 404", rec.Code, rec.Body)
	}
}
