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
		{
			name:     "provider-specific code",
			checkErr: &cmdb.Failure{Code: "missing_rest_profile", Message: "the user lacks a profile"},
			want:     `{"ok":false,"code":"missing_rest_profile","error":"the user lacks a profile"}`,
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

func TestTestCMDBSourceCredentialsRejectsMalformedJSON(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	rec := e.do(httptest.NewRequest(http.MethodPost, "/cmdb/source/test", strings.NewReader(`{"provider":`)))

	if rec.Code != http.StatusBadRequest {
		t.Errorf("response = %d %s, want 400", rec.Code, rec.Body)
	}
}
