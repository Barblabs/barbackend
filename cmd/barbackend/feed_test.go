package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"barbackend/internal/feeds/kev"
	"barbackend/internal/ingest"
)

const kevFixture = `{
  "catalogVersion": "2025.06.10",
  "dateReleased": "2025-06-10T16:59:42.000Z",
  "vulnerabilities": [
    {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j", "dateAdded": "2021-12-10", "shortDescription": "Log4j RCE", "requiredAction": "patch", "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2024-3094", "vendorProject": "XZ", "product": "xz", "dateAdded": "2024-03-29", "shortDescription": "xz backdoor", "requiredAction": "patch", "dueDate": "2024-04-19", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "not-a-cve", "vendorProject": "n", "product": "p", "dateAdded": "2024-03-29", "dueDate": "2024-04-19"}
  ]
}`

func TestFeedPull(t *testing.T) {
	var hits atomic.Int64
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = fmt.Fprint(w, kevFixture)
	}))
	t.Cleanup(fixture.Close)
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(broken.Close)

	good := ingest.Feed{Name: "kev", Interval: time.Hour, Pull: kev.New(fixture.Client(), fixture.URL).Pull}

	t.Run("single feed", func(t *testing.T) {
		var out bytes.Buffer
		if err := pullFeeds(context.Background(), &out, []ingest.Feed{good}, "kev"); err != nil {
			t.Fatal(err)
		}
		if got, want := out.String(), "kev: 2\n"; got != want {
			t.Errorf("output = %q, want %q", got, want)
		}
	})

	t.Run("all feeds", func(t *testing.T) {
		feeds := []ingest.Feed{good, {Name: "broken", Interval: time.Hour, Pull: kev.New(broken.Client(), broken.URL).Pull}}
		var out bytes.Buffer
		err := pullFeeds(context.Background(), &out, feeds, "")
		if err == nil {
			t.Fatal("err = nil, want a failure")
		}
		if !strings.Contains(out.String(), "kev: 2\n") {
			t.Errorf("output = %q, want the healthy Feed's count", out.String())
		}
		if !strings.Contains(out.String(), "broken: failed: ") {
			t.Errorf("output = %q, want the failing Feed reported", out.String())
		}
	})

	t.Run("unknown feed", func(t *testing.T) {
		before := hits.Load()
		var out bytes.Buffer
		err := pullFeeds(context.Background(), &out, []ingest.Feed{good}, "nvd")
		if !errors.Is(err, ingest.ErrUnknownFeed) {
			t.Errorf("err = %v, want ErrUnknownFeed", err)
		}
		if out.Len() != 0 {
			t.Errorf("output = %q, want nothing", out.String())
		}
		if hits.Load() != before {
			t.Error("unknown feed reached the network")
		}
	})
}
