package rest_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"barbackend/internal/cmdb/itop/rest"
)

type fakeITop struct {
	t       *testing.T
	ids     []int
	queries []string
}

var oqlPattern = regexp.MustCompile(`^SELECT Server WHERE id > (\d+)(?: AND id <= (\d+))?(?: AND \((.+)\))?$`)

func (f *fakeITop) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/itop/webservices/rest.php" || r.URL.Query().Get("version") != "1.4" {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Operation    string `json:"operation"`
		Key          string `json:"key"`
		OutputFields string `json:"output_fields"`
		Limit        int    `json:"limit"`
		Page         int    `json:"page"`
	}
	if err := json.Unmarshal([]byte(r.PostFormValue("json_data")), &req); err != nil || req.Operation != "core/get" || req.Page != 1 {
		f.t.Errorf("unexpected request %s", r.PostFormValue("json_data"))
		return
	}
	f.queries = append(f.queries, req.Key)
	m := oqlPattern.FindStringSubmatch(req.Key)
	if m == nil {
		f.t.Errorf("unexpected OQL %q", req.Key)
		return
	}
	after, _ := strconv.Atoi(m[1])
	upTo := int(^uint(0) >> 1)
	if m[2] != "" {
		upTo, _ = strconv.Atoi(m[2])
	}
	objects := map[string]any{}
	for i := len(f.ids) - 1; i >= 0 && len(objects) < req.Limit; i-- {
		if id := f.ids[i]; id > after && id <= upTo {
			objects[fmt.Sprintf("Server::%d", id)] = map[string]any{
				"code": 0, "message": "", "class": "Server", "key": strconv.Itoa(id),
				"fields": map[string]string{"name": fmt.Sprintf("server-%d", id)},
			}
		}
	}
	writeJSON(w, map[string]any{"code": 0, "message": fmt.Sprintf("Found: %d", len(objects)), "objects": objects})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func newClient(t *testing.T, h http.Handler, auth rest.Auth, opts rest.Options) *rest.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	base, err := url.Parse(srv.URL + "/itop")
	if err != nil {
		t.Fatal(err)
	}
	return rest.New(base, auth, opts)
}

func TestGetReadsEveryObjectOnce(t *testing.T) {
	t.Parallel()
	ids := []int{1, 2, 3, 40, 900, 901, 902, 903, 904, 905, 906, 5000}
	f := &fakeITop{t: t, ids: ids}
	c := newClient(t, f, rest.BasicAuth("reader", "secret"), rest.Options{PageSize: 2})

	got, err := c.Get(context.Background(), rest.Query{Class: "Server", Fields: []string{"name"}})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, o := range got {
		keys = append(keys, o.Key)
	}
	var want []string
	for _, id := range ids {
		want = append(want, strconv.Itoa(id))
	}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("keys = %v, want %v", keys, want)
	}
	if string(got[0].Fields) != `{"name":"server-1"}` || got[0].Class != "Server" {
		t.Errorf("first object = %+v", got[0])
	}
}

func TestGetNarrowsEveryQueryWithWhere(t *testing.T) {
	t.Parallel()
	f := &fakeITop{t: t, ids: []int{1, 7}}
	c := newClient(t, f, rest.BasicAuth("reader", "secret"), rest.Options{PageSize: 2})

	if _, err := c.Get(context.Background(), rest.Query{Class: "Server", Where: "status = 'production'"}); err != nil {
		t.Fatal(err)
	}
	for _, q := range f.queries {
		if !strings.HasSuffix(q, " AND (status = 'production')") {
			t.Errorf("query %q is not narrowed by the condition", q)
		}
	}
}

func TestGetAuthenticates(t *testing.T) {
	tests := []struct {
		name string
		auth rest.Auth
		ok   func(*http.Request) bool
	}{
		{"basic", rest.BasicAuth("reader", "secret"), func(r *http.Request) bool {
			return r.PostFormValue("auth_user") == "reader" && r.PostFormValue("auth_pwd") == "secret" && r.Header.Get("Auth-Token") == ""
		}},
		{"token", rest.TokenAuth("t0ken"), func(r *http.Request) bool {
			return r.Header.Get("Auth-Token") == "t0ken" && r.PostFormValue("auth_user") == ""
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeITop{t: t, ids: []int{1}}
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !tt.ok(r) {
					writeJSON(w, map[string]any{"code": 1, "message": "Error: Invalid login"})
					return
				}
				f.ServeHTTP(w, r)
			})
			c := newClient(t, h, tt.auth, rest.Options{})
			if _, err := c.Get(context.Background(), rest.Query{Class: "Server"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGetFails(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantAPI bool
	}{
		{"invalid login", http.StatusOK, `{"code": 1, "message": "Error: Invalid login"}`, true},
		{"invalid query", http.StatusOK, `{"code": 100, "message": "Error: Query failed to execute"}`, true},
		{"object error", http.StatusOK, `{"code": 0, "message": "Found: 1", "objects": {"Server::1": {"code": 100, "message": "broken", "class": "Server", "key": "1", "fields": {}}}}`, true},
		{"non-numeric key", http.StatusOK, `{"code": 0, "message": "Found: 1", "objects": {"Server::a": {"code": 0, "message": "", "class": "Server", "key": "a", "fields": {}}}}`, false},
		{"html page", http.StatusOK, `<html>Fatal error</html>`, false},
		{"server error", http.StatusInternalServerError, `{"code": 0}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			c := newClient(t, h, rest.BasicAuth("reader", "secret"), rest.Options{})
			_, err := c.Get(context.Background(), rest.Query{Class: "Server"})
			var apiErr *rest.APIError
			if err == nil || errors.As(err, &apiErr) != tt.wantAPI {
				t.Errorf("err = %v, want a failure that is an APIError: %v", err, tt.wantAPI)
			}
		})
	}
}

func TestGetTimesOut(t *testing.T) {
	t.Parallel()
	// Reading the body lets the server notice the client giving up.
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		<-r.Context().Done()
	})
	c := newClient(t, h, rest.BasicAuth("reader", "secret"), rest.Options{Timeout: 50 * time.Millisecond})
	// Canceling, not a deadline, so only the client's own Timeout yields a
	// timeout error; an ignored Timeout fails the test instead of passing late.
	ctx, cancel := context.WithCancel(context.Background())
	defer time.AfterFunc(10*time.Second, cancel).Stop()

	_, err := c.Get(ctx, rest.Query{Class: "Server"})

	var netErr net.Error
	if !errors.Is(err, rest.ErrTransport) || !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("err = %v, want a transport timeout", err)
	}
}
