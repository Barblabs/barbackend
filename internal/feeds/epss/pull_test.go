package epss_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"barbackend/internal/feeds/epss"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

// snapshot has the shape of FIRST's daily file, with one row that is not a
// CVE and one whose score is unreadable, both skipped.
const snapshot = `#model_version:v2025.03.14,score_date:2026-10-11T12:55:00Z
cve,epss,percentile
CVE-2025-49844,0.822940000,0.996550000
GHSA-0000-0000-0000,0.1,0.2
CVE-2025-0001,high,0.9
`

func TestPullEmitsEachScoreOfTheSnapshot(t *testing.T) {
	t.Parallel()
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write([]byte(snapshot)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(gz.Bytes()) }))
	t.Cleanup(srv.Close)

	var got []*stix2.Vulnerability
	err := epss.New(srv.Client(), srv.URL).Pull(context.Background(), func(o stix2.STIXObject) error {
		got = append(got, o.(*stix2.Vulnerability))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 1 || got[0].Name != "CVE-2025-49844" {
		t.Fatalf("emitted %+v, want CVE-2025-49844 alone", got)
	}
	score, ok := stixext.EPSSOf(got[0])
	want := stixext.NewEPSS(stixext.EPSS{Probability: 0.82294, Percentile: 0.99655, ScoreDate: "2026-10-11", ModelVersion: "v2025.03.14"})
	if !ok || score != want {
		t.Errorf("score = %+v, %v; want %+v", score, ok, want)
	}
}
