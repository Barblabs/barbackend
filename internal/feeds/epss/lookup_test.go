package epss_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"barbackend/internal/feeds/epss"
	"barbackend/internal/stixext"
)

func TestLookup(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, body string
		want       float64
		listed     bool
	}{
		{
			name:   "scored",
			body:   `{"status":"OK","data":[{"cve":"CVE-2025-49844","epss":"0.822940000","percentile":"0.996550000","date":"2026-10-11"}]}`,
			want:   0.82294,
			listed: true,
		},
		{name: "not scored", body: `{"status":"OK","data":[]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var query string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query = r.URL.RawQuery
				_, _ = w.Write([]byte(tt.body))
			}))
			t.Cleanup(srv.Close)

			v, err := epss.New(srv.Client(), "", srv.URL).Lookup(context.Background(), "CVE-2025-49844")
			if err != nil {
				t.Fatal(err)
			}
			if query != "cve=CVE-2025-49844" {
				t.Errorf("query = %q", query)
			}
			if !tt.listed {
				if v != nil {
					t.Errorf("v = %+v, want nil", v)
				}
				return
			}
			score, ok := stixext.EPSSOf(v)
			if !ok || score.Probability != tt.want || score.ScoreDate != "2026-10-11" {
				t.Errorf("score = %+v, %v", score, ok)
			}
		})
	}
}

func TestLookupFailsOnAnUnreadableScore(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"cve":"CVE-2025-49844","epss":"high","percentile":"0.9","date":"2026-10-11"}]}`))
	}))
	t.Cleanup(srv.Close)

	if _, err := epss.New(srv.Client(), "", srv.URL).Lookup(context.Background(), "CVE-2025-49844"); err == nil {
		t.Error("err = nil, want a failure, not a missing score")
	}
}
