package nvd_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"barbackend/internal/feeds/nvd"
	"github.com/TcM1911/stix2"
)

func pull(t *testing.T, body string) ([]*stix2.Vulnerability, url.Values) {
	t.Helper()
	var query url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query()
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	var got []*stix2.Vulnerability
	err := nvd.New(srv.Client(), srv.URL, "").Pull(context.Background(), func(o stix2.STIXObject) error {
		got = append(got, o.(*stix2.Vulnerability))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got, query
}
