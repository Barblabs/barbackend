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
	tokenSettings = `{"url": "http://localhost:8000", "auth": {"mode": "token"}}`
	password      = `{"password": "secret"}`
	token         = `{"token": "t0ken"}`
)

func TestParseSettings(t *testing.T) {
	tests := []struct {
		name        string
		settings    string
		credentials string
		want        error
	}{
		{"basic", `{"url": "https://itop.example.com", "auth": {"mode": "basic", "user": "barb-reader"}}`, password, nil},
		{"token", tokenSettings, token, nil},
		{"url with path", `{"url": "https://example.com/itop", "auth": {"mode": "token"}}`, token, nil},
		{"not an object", `[]`, token, itop.ErrInvalidSettings},
		{"data after the object", tokenSettings + ` {}`, token, itop.ErrInvalidSettings},
		{"unknown field", `{"url": "http://localhost:8000", "auth": {"mode": "token"}, "password": "secret"}`, token, itop.ErrInvalidSettings},
		{"no url", `{"auth": {"mode": "token"}}`, token, itop.ErrInvalidSettings},
		{"relative url", `{"url": "localhost:8000", "auth": {"mode": "token"}}`, token, itop.ErrInvalidSettings},
		{"ftp url", `{"url": "ftp://localhost", "auth": {"mode": "token"}}`, token, itop.ErrInvalidSettings},
		{"credentials in url", `{"url": "http://admin:secret@localhost:8000", "auth": {"mode": "token"}}`, token, itop.ErrInvalidSettings},
		{"query in url", `{"url": "http://localhost:8000/webservices/rest.php?version=1.3", "auth": {"mode": "token"}}`, token, itop.ErrInvalidSettings},
		{"no auth", `{"url": "http://localhost:8000"}`, token, itop.ErrInvalidSettings},
		{"unknown mode", `{"url": "http://localhost:8000", "auth": {"mode": "oauth"}}`, token, itop.ErrInvalidSettings},
		{"basic without user", `{"url": "http://localhost:8000", "auth": {"mode": "basic", "user": " "}}`, password, itop.ErrInvalidSettings},
		{"token with user", `{"url": "http://localhost:8000", "auth": {"mode": "token", "user": "barb-reader"}}`, token, itop.ErrInvalidSettings},
		{"password_env", `{"url": "http://localhost:8000", "auth": {"mode": "basic", "user": "barb-reader", "password_env": "ITOP_PASSWORD"}}`, password, itop.ErrInvalidSettings},
		{"token_env", `{"url": "http://localhost:8000", "auth": {"mode": "token", "token_env": "ITOP_TOKEN"}}`, token, itop.ErrInvalidSettings},
		{"credentials not an object", basicSettings, `"secret"`, itop.ErrInvalidCredentials},
		{"credentials unknown field", basicSettings, `{"password": "secret", "user": "admin"}`, itop.ErrInvalidCredentials},
		{"basic without password", basicSettings, `{"password": ""}`, itop.ErrInvalidCredentials},
		{"basic with token", basicSettings, `{"password": "secret", "token": "t0ken"}`, itop.ErrInvalidCredentials},
		{"token without token", tokenSettings, `{}`, itop.ErrInvalidCredentials},
		{"token with password", tokenSettings, `{"token": "t0ken", "password": "secret"}`, itop.ErrInvalidCredentials},
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
		{"token", tokenSettings, cmdb.Description{URL: "http://localhost:8000"}, nil},
		{"invalid", `{"auth": {"mode": "token"}}`, cmdb.Description{}, itop.ErrInvalidSettings},
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

// A Snapshot authenticates with the credentials it was parsed with. The fake
// iTop refuses anything else, as iTop does with HTTP 200 and a non-zero code.
func TestSnapshotAuthenticatesWithCredentials(t *testing.T) {
	tests := []struct {
		name        string
		auth        string
		credentials string
		accepted    func(r *http.Request) bool
	}{
		{"basic", `{"mode": "basic", "user": "barb-reader"}`, password, func(r *http.Request) bool {
			return r.PostFormValue("auth_user") == "barb-reader" && r.PostFormValue("auth_pwd") == "secret"
		}},
		{"token", `{"mode": "token"}`, token, func(r *http.Request) bool {
			return r.Header.Get("Auth-Token") == "t0ken"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !tt.accepted(r) {
					_, _ = w.Write([]byte(`{"code": 1, "message": "Error: Invalid login"}`))
					return
				}
				_, _ = w.Write([]byte(`{"code": 0, "message": "Found: 0", "objects": null}`))
			}))
			t.Cleanup(srv.Close)
			settings := `{"url": "` + srv.URL + `", "auth": ` + tt.auth + `}`
			parsed, err := (itop.Provider{}).ParseSettings(json.RawMessage(settings), json.RawMessage(tt.credentials))
			if err != nil {
				t.Fatal(err)
			}

			if _, err := parsed.Snapshot(context.Background()); err != nil {
				t.Errorf("snapshot: %v", err)
			}
		})
	}
}
