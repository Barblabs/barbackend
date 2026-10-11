package itop_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"barbackend/internal/cmdb/itop"
)

func TestParseSettings(t *testing.T) {
	tests := []struct {
		name     string
		settings string
		want     error
	}{
		{"basic", `{"url": "https://itop.example.com", "auth": {"mode": "basic", "user": "barb-reader", "password_env": "ITOP_PASSWORD"}}`, nil},
		{"token", `{"url": "http://localhost:8000", "auth": {"mode": "token", "token_env": "ITOP_TOKEN"}}`, nil},
		{"url with path", `{"url": "https://example.com/itop", "auth": {"mode": "token", "token_env": "ITOP_TOKEN"}}`, nil},
		{"not an object", `[]`, itop.ErrInvalidSettings},
		{"data after the object", `{"url": "http://localhost:8000", "auth": {"mode": "token", "token_env": "ITOP_TOKEN"}} {}`, itop.ErrInvalidSettings},
		{"unknown field", `{"url": "http://localhost:8000", "auth": {"mode": "token", "token_env": "ITOP_TOKEN"}, "password": "secret"}`, itop.ErrInvalidSettings},
		{"no url", `{"auth": {"mode": "token", "token_env": "ITOP_TOKEN"}}`, itop.ErrInvalidSettings},
		{"relative url", `{"url": "localhost:8000", "auth": {"mode": "token", "token_env": "ITOP_TOKEN"}}`, itop.ErrInvalidSettings},
		{"ftp url", `{"url": "ftp://localhost", "auth": {"mode": "token", "token_env": "ITOP_TOKEN"}}`, itop.ErrInvalidSettings},
		{"credentials in url", `{"url": "http://admin:secret@localhost:8000", "auth": {"mode": "token", "token_env": "ITOP_TOKEN"}}`, itop.ErrInvalidSettings},
		{"query in url", `{"url": "http://localhost:8000/webservices/rest.php?version=1.3", "auth": {"mode": "token", "token_env": "ITOP_TOKEN"}}`, itop.ErrInvalidSettings},
		{"no auth", `{"url": "http://localhost:8000"}`, itop.ErrInvalidSettings},
		{"unknown mode", `{"url": "http://localhost:8000", "auth": {"mode": "oauth"}}`, itop.ErrInvalidSettings},
		{"basic without user", `{"url": "http://localhost:8000", "auth": {"mode": "basic", "user": " ", "password_env": "ITOP_PASSWORD"}}`, itop.ErrInvalidSettings},
		{"basic without password_env", `{"url": "http://localhost:8000", "auth": {"mode": "basic", "user": "barb-reader"}}`, itop.ErrInvalidSettings},
		{"basic with token_env", `{"url": "http://localhost:8000", "auth": {"mode": "basic", "user": "barb-reader", "password_env": "ITOP_PASSWORD", "token_env": "ITOP_TOKEN"}}`, itop.ErrInvalidSettings},
		{"token without token_env", `{"url": "http://localhost:8000", "auth": {"mode": "token"}}`, itop.ErrInvalidSettings},
		{"token with user", `{"url": "http://localhost:8000", "auth": {"mode": "token", "token_env": "ITOP_TOKEN", "user": "barb-reader"}}`, itop.ErrInvalidSettings},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := (itop.Provider{}).ParseSettings(json.RawMessage(tt.settings)); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

// Secrets are read from the environment by the process that syncs, so a
// missing one only shows when a Sync starts.
func TestSnapshotNeedsSecret(t *testing.T) {
	tests := []struct {
		name     string
		settings string
		env      string
	}{
		{"basic", `{"url": "http://localhost:8000", "auth": {"mode": "basic", "user": "barb-reader", "password_env": "BARB_TEST_ITOP_PASSWORD"}}`, "BARB_TEST_ITOP_PASSWORD"},
		{"token", `{"url": "http://localhost:8000", "auth": {"mode": "token", "token_env": "BARB_TEST_ITOP_TOKEN"}}`, "BARB_TEST_ITOP_TOKEN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.env, "")
			settings, err := (itop.Provider{}).ParseSettings(json.RawMessage(tt.settings))
			if err != nil {
				t.Fatal(err)
			}
			_, err = settings.Snapshot(context.Background())
			if !errors.Is(err, itop.ErrMissingSecret) {
				t.Fatalf("err = %v, want %v", err, itop.ErrMissingSecret)
			}
			if want := itop.ErrMissingSecret.Error() + ": " + tt.env; err.Error() != want {
				t.Errorf("err = %q, want it to name the variable: %q", err, want)
			}
		})
	}
}
