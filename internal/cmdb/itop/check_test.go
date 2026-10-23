package itop_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"barbackend/internal/cmdb"
	"barbackend/internal/cmdb/itop"
)

const (
	fakeUser     = "barb-reader"
	fakePassword = "s3cret"
)

func fakeITop(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/webservices/rest.php" || r.PostFormValue("json_data") != `{"operation":"list_operations"}` {
		http.NotFound(w, r)
		return
	}
	switch {
	case r.PostFormValue("auth_user") != fakeUser || r.PostFormValue("auth_pwd") != fakePassword:
		_, _ = w.Write([]byte(`{"code":1,"message":"Error: Invalid login"}`))
	default:
		_, _ = w.Write([]byte(`{"code":0,"message":"Operations: 1","version":"1.4","operations":[{"verb":"core\/get","description":"Search for objects","extension":"CoreServices"}]}`))
	}
}

func reply(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }
}

func checkCredentials(ctx context.Context, t *testing.T, url, password string) error {
	t.Helper()
	settings, credentials, err := itop.Provider{}.FromLogin(cmdb.Login{URL: url, User: fakeUser, Password: password})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := itop.Provider{}.ParseSettings(settings, credentials)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.CheckCredentials(ctx)
}

func TestCheckCredentialsSucceeds(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(fakeITop))
	t.Cleanup(srv.Close)

	if err := checkCredentials(context.Background(), t, srv.URL, fakePassword); err != nil {
		t.Errorf("CheckCredentials = %v, want nil", err)
	}
}

func TestCheckCredentialsFailureCodes(t *testing.T) {
	t.Parallel()
	closed := httptest.NewServer(http.HandlerFunc(fakeITop))
	closed.Close()

	tests := []struct {
		name     string
		url      func(t *testing.T) string
		password string
		timeout  time.Duration
		want     cmdb.FailureCode
	}{
		{
			name:     "wrong password",
			url:      serve(http.HandlerFunc(fakeITop)),
			password: "wrong",
			want:     cmdb.RejectedLogin,
		},
		{
			name: "user without the REST profile",
			url: serve(reply(`{"code":1,"message":"Error: This user is not authorized to use the web services. ` +
				`(The profile REST Services User is required to access the REST web services)"}`)),
			want: "missing_rest_profile",
		},
		{
			name: "connection refused",
			url:  func(*testing.T) string { return closed.URL },
			want: cmdb.Unreachable,
		},
		{
			name: "unknown host",
			url:  func(*testing.T) string { return "http://itop.invalid" },
			want: cmdb.Unreachable,
		},
		{
			name: "timeout",
			url: func(t *testing.T) string {
				release := make(chan struct{})
				srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
				t.Cleanup(srv.Close)
				t.Cleanup(func() { close(release) })
				return srv.URL
			},
			timeout: 100 * time.Millisecond,
			want:    cmdb.Unreachable,
		},
		{
			name: "untrusted certificate",
			url: func(t *testing.T) string {
				srv := httptest.NewTLSServer(http.HandlerFunc(fakeITop))
				t.Cleanup(srv.Close)
				return srv.URL
			},
			want: cmdb.TLSError,
		},
		{
			name: "https to a plain http server",
			url: func(t *testing.T) string {
				srv := httptest.NewServer(http.HandlerFunc(fakeITop))
				t.Cleanup(srv.Close)
				return "https://" + srv.Listener.Addr().String()
			},
			want: cmdb.TLSError,
		},
		{
			name: "not found",
			url:  serve(http.NotFoundHandler()),
			want: cmdb.UnexpectedResponse,
		},
		{
			name: "html page",
			url:  serve(reply(`<html><body>Fatal error</body></html>`)),
			want: cmdb.UnexpectedResponse,
		},
		{
			name: "json that is not iTop",
			url:  serve(reply(`{}`)),
			want: cmdb.UnexpectedResponse,
		},
		{
			name: "another iTop error",
			url:  serve(reply(`{"code":10,"message":"Error: Unsupported version"}`)),
			want: cmdb.UnexpectedResponse,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			password := tt.password
			if password == "" {
				password = fakePassword
			}
			ctx := context.Background()
			if tt.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.timeout)
				defer cancel()
			}

			err := checkCredentials(ctx, t, tt.url(t), password)

			var failure *cmdb.Failure
			if !errors.As(err, &failure) || failure.Code != tt.want || failure.Message == "" {
				t.Errorf("CheckCredentials = %#v, want a %s failure with a message", err, tt.want)
			}
		})
	}
}

func serve(h http.Handler) func(t *testing.T) string {
	return func(t *testing.T) string {
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		return srv.URL
	}
}

func snapshot(t *testing.T, url string) error {
	t.Helper()
	settings, credentials, err := itop.Provider{}.FromLogin(cmdb.Login{URL: url, User: fakeUser, Password: fakePassword})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := itop.Provider{}.ParseSettings(settings, credentials)
	if err != nil {
		t.Fatal(err)
	}
	_, err = parsed.Snapshot(context.Background())
	return err
}

func TestSnapshotFailureCodes(t *testing.T) {
	t.Parallel()
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	tests := []struct {
		name string
		url  func(t *testing.T) string
		want cmdb.FailureCode
	}{
		{"rejected login", serve(reply(`{"code":1,"message":"Error: Invalid login"}`)), cmdb.RejectedLogin},
		{"connection refused", func(*testing.T) string { return closed.URL }, cmdb.Unreachable},
		{"html page", serve(reply(`<html><body>Fatal error</body></html>`)), cmdb.UnexpectedResponse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := snapshot(t, tt.url(t))

			var failure *cmdb.Failure
			if !errors.As(err, &failure) || failure.Code != tt.want {
				t.Errorf("Snapshot = %v, want a %s failure", err, tt.want)
			}
		})
	}
}

func TestSnapshotKeepsItsOwnErrorsUnclassified(t *testing.T) {
	t.Parallel()
	url := serve(reply(`{"code":0,"message":"","objects":{"Server::abc":{"code":0,"message":"","class":"Server","key":"abc","fields":{}}}}`))(t)

	err := snapshot(t, url)

	var failure *cmdb.Failure
	if err == nil || errors.As(err, &failure) {
		t.Errorf("Snapshot = %#v, want an unclassified error", err)
	}
}
