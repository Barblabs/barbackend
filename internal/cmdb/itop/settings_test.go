package itop_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"barbackend/internal/cmdb"
	"barbackend/internal/cmdb/itop"
)

const (
	basicSettings = `{"url": "http://localhost:8000", "auth": {"mode": "basic", "user": "barb-reader"}}`
	password      = `{"password": "secret"}`
)

func TestParseSettings(t *testing.T) {
	tests := []struct {
		name        string
		settings    string
		credentials string
		want        error
	}{
		{"basic", `{"url": "https://itop.example.com", "auth": {"mode": "basic", "user": "barb-reader"}}`, password, nil},
		{"url with path", `{"url": "https://example.com/itop", "auth": {"mode": "basic", "user": "barb-reader"}}`, password, nil},
		{"not an object", `[]`, password, itop.ErrInvalidSettings},
		{"data after the object", basicSettings + ` {}`, password, itop.ErrInvalidSettings},
		{"unknown field", `{"url": "http://localhost:8000", "auth": {"mode": "basic", "user": "barb-reader"}, "password": "secret"}`, password, itop.ErrInvalidSettings},
		{"no url", `{"auth": {"mode": "basic", "user": "barb-reader"}}`, password, itop.ErrInvalidSettings},
		{"relative url", `{"url": "localhost:8000", "auth": {"mode": "basic", "user": "barb-reader"}}`, password, itop.ErrInvalidSettings},
		{"ftp url", `{"url": "ftp://localhost", "auth": {"mode": "basic", "user": "barb-reader"}}`, password, itop.ErrInvalidSettings},
		{"credentials in url", `{"url": "http://admin:secret@localhost:8000", "auth": {"mode": "basic", "user": "barb-reader"}}`, password, itop.ErrInvalidSettings},
		{"query in url", `{"url": "http://localhost:8000/webservices/rest.php?version=1.3", "auth": {"mode": "basic", "user": "barb-reader"}}`, password, itop.ErrInvalidSettings},
		{"no auth", `{"url": "http://localhost:8000"}`, password, itop.ErrInvalidSettings},
		{"token mode", `{"url": "http://localhost:8000", "auth": {"mode": "token"}}`, `{"token": "t0ken"}`, itop.ErrInvalidSettings},
		{"basic without user", `{"url": "http://localhost:8000", "auth": {"mode": "basic", "user": " "}}`, password, itop.ErrInvalidSettings},
		{"password_env", `{"url": "http://localhost:8000", "auth": {"mode": "basic", "user": "barb-reader", "password_env": "ITOP_PASSWORD"}}`, password, itop.ErrInvalidSettings},
		{"credentials not an object", basicSettings, `"secret"`, itop.ErrInvalidCredentials},
		{"credentials unknown field", basicSettings, `{"password": "secret", "user": "admin"}`, itop.ErrInvalidCredentials},
		{"basic without password", basicSettings, `{"password": ""}`, itop.ErrInvalidCredentials},
		{"basic with token", basicSettings, `{"password": "secret", "token": "t0ken"}`, itop.ErrInvalidCredentials},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := (itop.Provider{}).ParseSettings(json.RawMessage(tt.settings), json.RawMessage(tt.credentials)); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDescribe(t *testing.T) {
	tests := []struct {
		name     string
		settings string
		want     cmdb.Description
		wantErr  error
	}{
		{"basic", basicSettings, cmdb.Description{URL: "http://localhost:8000", User: "barb-reader"}, nil},
		{"invalid", `{"auth": {"mode": "basic", "user": "barb-reader"}}`, cmdb.Description{}, itop.ErrInvalidSettings},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := (itop.Provider{}).Describe(json.RawMessage(tt.settings))
			if !errors.Is(err, tt.wantErr) || got != tt.want {
				t.Errorf("Describe = %+v, %v, want %+v, %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestSnapshotAuthenticatesWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.PostFormValue("auth_user") != "barb-reader" || r.PostFormValue("auth_pwd") != "secret" {
			_, _ = w.Write([]byte(`{"code": 1, "message": "Error: Invalid login"}`))
			return
		}
		_, _ = w.Write([]byte(`{"code": 0, "message": "Found: 0", "objects": null}`))
	}))
	t.Cleanup(srv.Close)
	settings := `{"url": "` + srv.URL + `", "auth": {"mode": "basic", "user": "barb-reader"}}`
	parsed, err := (itop.Provider{}).ParseSettings(json.RawMessage(settings), json.RawMessage(password))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := parsed.Snapshot(context.Background()); err != nil {
		t.Errorf("snapshot: %v", err)
	}
}
