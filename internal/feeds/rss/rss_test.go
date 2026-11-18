package rss_test

import (
	"context"
	_ "embed"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"barbackend/internal/feeds/rss"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

const feed = "example"

var (
	//go:embed testdata/rss.xml
	rssFeed []byte
	//go:embed testdata/atom.xml
	atomFeed []byte
)

func pull(t *testing.T, name string, body []byte) ([]*stix2.Report, error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(srv.Close)
	var got []*stix2.Report
	a := rss.New(srv.Client(), rss.Config{Name: name, URL: srv.URL, Language: "en"})
	err := a.Pull(context.Background(), func(o stix2.STIXObject) error {
		got = append(got, o.(*stix2.Report))
		return nil
	})
	return got, err
}

// roundTrip is reports as a consumer reads them back, through stix2.FromJSON.
func roundTrip(t *testing.T, reports []*stix2.Report) *stix2.Collection {
	t.Helper()
	raw, err := json.Marshal(reports)
	if err != nil {
		t.Fatal(err)
	}
	c, err := stix2.FromJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type want struct {
	key, name, description, link, guid string
	published                          time.Time
	objects                            []stix2.Identifier
}

func check(t *testing.T, c *stix2.Collection, w want) {
	t.Helper()
	id := stixext.ID(stix2.TypeReport, feed+":"+w.key)
	r := c.Report(id)
	if r == nil {
		t.Fatalf("no report %s for %s", id, w.key)
	}
	if r.Name != w.name || r.Description != w.description {
		t.Errorf("%s: name, description = %q, %q; want %q, %q", w.key, r.Name, r.Description, w.name, w.description)
	}
	if !r.Published.Equal(w.published) {
		t.Errorf("%s: published = %v, want %v", w.key, r.Published.Time, w.published)
	}
	if !slices.Equal(r.Objects, w.objects) {
		t.Errorf("%s: object_refs = %v, want %v", w.key, r.Objects, w.objects)
	}
	if r.CreatedBy != stixext.BarbattackID || !slices.Equal(r.ObjectMarking, []stix2.Identifier{stixext.TLPClear}) {
		t.Errorf("%s: created_by_ref, object_marking_refs = %v, %v; want barbattack, TLP:CLEAR", w.key, r.CreatedBy, r.ObjectMarking)
	}
	type reference struct{ name, url, externalID string }
	refs := []reference{{feed, w.link, ""}}
	if w.guid != "" {
		refs = append(refs, reference{"guid", "", w.guid})
	}
	var got []reference
	for _, ref := range r.ExternalReferences {
		got = append(got, reference{ref.Name, ref.URL, ref.ExternalID})
	}
	if !slices.Equal(got, refs) {
		t.Errorf("%s: external_references = %+v, want %+v", w.key, got, refs)
	}
	news, ok := stixext.NewsOf(r)
	wantNews := stixext.NewNews(stixext.News{Feed: feed, Kind: stixext.NewsArticle, Language: "en", Link: w.link})
	if !ok || news != wantNews {
		t.Errorf("%s: news/1 = %+v, %v; want %+v", w.key, news, ok, wantNews)
	}
}

func TestPullReadsAnRSSFeed(t *testing.T) {
	t.Parallel()
	got, err := pull(t, feed, rssFeed)
	if err != nil {
		t.Fatal(err)
	}

	// The items without a date, with an unreadable one, and with neither a
	// guid nor a web link are skipped.
	if len(got) != 3 {
		t.Fatalf("emitted %d reports, want 3", len(got))
	}
	c := roundTrip(t, got)
	check(t, c, want{
		key:         "https://news.example.com/?p=101",
		guid:        "https://news.example.com/?p=101",
		name:        "Acme & Co. VPN flaw exploited",
		description: "Attackers exploit CVE-2026-1234 & cve-2026-5678 in Acme’s VPN. The post Acme VPN appeared first on Example News.",
		link:        "https://news.example.com/acme-vpn-flaw-exploited/",
		published:   time.Date(2026, 11, 17, 14, 55, 30, 0, time.UTC),
		objects:     []stix2.Identifier{stixext.VulnerabilityID("CVE-2026-1234"), stixext.VulnerabilityID("CVE-2026-5678")},
	})
	check(t, c, want{
		key:         "https://news.example.com/hospital-data-stolen/",
		name:        "Hospital chain says patient data was stolen",
		description: "A regional hospital chain said attackers stole patient records.",
		link:        "https://news.example.com/hospital-data-stolen/",
		published:   time.Date(2026, 11, 4, 1, 20, 0, 0, time.UTC),
		objects:     []stix2.Identifier{stixext.BarbattackID},
	})
	check(t, c, want{
		key:         "https://news.example.com/?p=106",
		guid:        "https://news.example.com/?p=106",
		name:        "Banco sufre un ataque de ransomware",
		description: "El banco confirmó el ataque.",
		link:        "https://news.example.com/banco-ransomware/?utm_source=rss",
		published:   time.Date(2026, 11, 16, 14, 30, 0, 0, time.UTC),
		objects:     []stix2.Identifier{stixext.BarbattackID},
	})
}

func TestPullReadsAnAtomFeed(t *testing.T) {
	t.Parallel()
	got, err := pull(t, feed, atomFeed)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 2 {
		t.Fatalf("emitted %d reports, want 2: the entry without a date is skipped", len(got))
	}
	c := roundTrip(t, got)
	check(t, c, want{
		key:         "tag:blog.example.org,2026:acme",
		guid:        "tag:blog.example.org,2026:acme",
		name:        "Ransomware hits Acme",
		description: "Acme confirms the attack, through CVE-2026-0001.",
		link:        "https://blog.example.org/acme",
		published:   time.Date(2026, 11, 16, 14, 30, 0, 0, time.UTC),
		objects:     []stix2.Identifier{stixext.VulnerabilityID("CVE-2026-0001")},
	})
	check(t, c, want{
		key:         "tag:blog.example.org,2026:patch-notes",
		guid:        "tag:blog.example.org,2026:patch-notes",
		name:        "Patch notes",
		description: "An xhtml body. Second paragraph.",
		link:        "https://blog.example.org/patch-notes",
		published:   time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC),
		objects:     []stix2.Identifier{stixext.BarbattackID},
	})
}

func TestPullMintsTheSameIDsEachTimeAndOnePerFeed(t *testing.T) {
	t.Parallel()
	ids := func(name string) []stix2.Identifier {
		got, err := pull(t, name, rssFeed)
		if err != nil {
			t.Fatal(err)
		}
		var ids []stix2.Identifier
		for _, r := range got {
			ids = append(ids, r.ID)
		}
		return ids
	}

	first, again, other := ids(feed), ids(feed), ids("other")
	if !slices.Equal(first, again) {
		t.Errorf("ids = %v, then %v; want the same", first, again)
	}
	for _, id := range other {
		if slices.Contains(first, id) {
			t.Errorf("%s is minted by two Feeds; want each Feed's own", id)
		}
	}
}

func TestPullFailsOnAPageThatIsNotAFeed(t *testing.T) {
	t.Parallel()
	_, err := pull(t, feed, []byte(`<html><head><title>Just a moment...</title></head><body></body></html>`))
	if err == nil {
		t.Error("err = nil, want a failure, not an empty Feed")
	}
}

func TestDefaultsNameEachFeedOnce(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, c := range rss.Defaults() {
		if c.Name != strings.ToLower(c.Name) || strings.ContainsAny(c.Name, " \t") || seen[c.Name] {
			t.Errorf("name %q: want lowercase, without spaces and unique", c.Name)
		}
		seen[c.Name] = true
		if !strings.HasPrefix(c.URL, "https://") || (c.Language != "en" && c.Language != "es") {
			t.Errorf("%s: url, language = %q, %q; want https and en or es", c.Name, c.URL, c.Language)
		}
	}
}
