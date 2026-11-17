package ransomwarelive_test

import (
	"context"
	_ "embed"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"barbackend/internal/feeds/ransomwarelive"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

const feed = "ransomwarelive"

// recentVictims is seven posts of a real list, their descriptions shortened.
//
//go:embed testdata/recentvictims.json
var recentVictims []byte

func pull(t *testing.T, body []byte) ([]stix2.STIXObject, error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(srv.Close)
	var got []stix2.STIXObject
	err := ransomwarelive.New(srv.Client(), srv.URL).Pull(context.Background(), func(o stix2.STIXObject) error {
		got = append(got, o)
		return nil
	})
	return got, err
}

// roundTrip is objs as a consumer reads them back, through stix2.FromJSON.
func roundTrip(t *testing.T, objs []stix2.STIXObject) *stix2.Collection {
	t.Helper()
	raw, err := json.Marshal(objs)
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
	key, name, domain, attacker, link string
	published                         time.Time
	countries, sectors                []string
	objects                           []stix2.Identifier
}

// check asserts that c holds the victim and the report that w describes.
func check(t *testing.T, c *stix2.Collection, w want) {
	t.Helper()
	id := stixext.VictimID(w.domain, feed, w.key)
	checkVictim(t, c.Identity(id), w)
	checkReport(t, c.Report(stixext.ID(stix2.TypeReport, feed+":"+w.key)), id, w)
}

func checkVictim(t *testing.T, v *stix2.Identity, w want) {
	t.Helper()
	if v == nil {
		t.Fatalf("%s: no victim", w.key)
	}
	if v.Name != w.name || v.Class != stix2.IdentityClassOrganization || !slices.Equal(v.Sectors, w.sectors) {
		t.Errorf("%s: victim name, class, sectors = %q, %q, %v; want %q, organization, %v", w.key, v.Name, v.Class, v.Sectors, w.name, w.sectors)
	}
	ext, ok := stixext.VictimOf(v)
	if !ok || ext.ExtensionType != "property-extension" || ext.Domain != w.domain || !slices.Equal(ext.Countries, w.countries) {
		t.Errorf("%s: victim/1 = %+v, %v; want domain %q, countries %v", w.key, ext, ok, w.domain, w.countries)
	}
	checkMinted(t, &v.STIXDomainObject)
}

func checkReport(t *testing.T, r *stix2.Report, victim stix2.Identifier, w want) {
	t.Helper()
	if r == nil {
		t.Fatalf("%s: no report", w.key)
	}
	if r.Name != w.name || !r.Published.Equal(w.published) {
		t.Errorf("%s: report name, published = %q, %v; want %q, %v", w.key, r.Name, r.Published.Time, w.name, w.published)
	}
	if objects := append([]stix2.Identifier{victim}, w.objects...); !slices.Equal(r.Objects, objects) {
		t.Errorf("%s: object_refs = %v, want %v", w.key, r.Objects, objects)
	}
	var links, wantLinks []string
	for _, ref := range r.ExternalReferences {
		links = append(links, ref.Name+" "+ref.URL)
	}
	if w.link != "" {
		wantLinks = []string{feed + " " + w.link}
	}
	if !slices.Equal(links, wantLinks) {
		t.Errorf("%s: external_references = %v, want %v", w.key, links, wantLinks)
	}
	news, ok := stixext.NewsOf(r)
	wantNews := stixext.NewNews(stixext.News{Feed: feed, Kind: stixext.NewsLeakPost, Attacker: w.attacker, Link: w.link})
	if !ok || news != wantNews {
		t.Errorf("%s: news/1 = %+v, %v; want %+v", w.key, news, ok, wantNews)
	}
	checkMinted(t, &r.STIXDomainObject)
}

func checkMinted(t *testing.T, o *stix2.STIXDomainObject) {
	t.Helper()
	if o.CreatedBy != stixext.BarbattackID || !slices.Equal(o.ObjectMarking, []stix2.Identifier{stixext.TLPClear}) {
		t.Errorf("%s: created_by_ref, object_marking_refs = %v, %v; want barbattack, TLP:CLEAR", o.ID, o.CreatedBy, o.ObjectMarking)
	}
}

func TestPullEmitsEachVictimBeforeItsPost(t *testing.T) {
	t.Parallel()
	got, err := pull(t, recentVictims)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 14 {
		t.Fatalf("emitted %d objects, want a victim and a report for each of the 7 posts", len(got))
	}
	for i := 0; i < len(got); i += 2 {
		v, isVictim := got[i].(*stix2.Identity)
		r, isReport := got[i+1].(*stix2.Report)
		if !isVictim || !isReport {
			t.Fatalf("objects %d and %d are %T and %T, want the victim and then its report", i, i+1, got[i], got[i+1])
		}
		if r.Objects[0] != v.ID {
			t.Errorf("report %s refers first to %s, want its victim %s", r.ID, r.Objects[0], v.ID)
		}
	}
	c := roundTrip(t, got)
	const id = "https://www.ransomware.live/id/"
	for _, w := range []want{
		{key: id + "TmV3IEVuZ2xhbmQgT3J0aG9wZWRpYyBTdXJnZW9uc0BCb29iYSBQcm9qZWN0", name: "New England Orthopedic Surgeons", domain: "neortho.com",
			attacker: "Booba Project", published: time.Date(2026, 11, 17, 13, 16, 11, 437000000, time.UTC), countries: []string{"US"}, sectors: []string{"healthcare"}},
		{key: id + "Q2FsaWZvcm5pYSBDcm9zcyBEb2NrQHFpbGlu", name: "California Cross Dock", domain: "californiacrossdock.com",
			attacker: "qilin", published: time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC), countries: []string{"US"}, sectors: []string{"transportation"}},
		{key: id + "U2ljZSBQcmV2aXQgUy5wLkEuQGF1cm9yYQ==", name: "Sice Previt S.p.A.",
			attacker: "aurora", published: time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC), countries: []string{"IT"}, sectors: []string{"manufacturing"}},
		{key: id + "SSoqKioqKiBBKioqKipAbmV0cnVubmVy", name: "I****** A*****",
			attacker: "netrunner", published: time.Date(2026, 11, 14, 1, 30, 50, 207000000, time.UTC), countries: []string{"KW"}},
		{key: id + "U3RlZmZlbiBmYW1pbHkgcmV0YWlsIGdyb3VwQHJoeXNpZGE=", name: "Steffen family retail group",
			attacker: "rhysida", published: time.Date(2026, 11, 16, 14, 24, 39, 17000000, time.UTC), sectors: []string{"retail", "e-commerce"}},
		{key: id + "QkhJQyBCb2ZvcnMgQXNpYUBpbmNyYW5zb20=", name: "BHIC Bofors Asia",
			attacker: "incransom", published: time.Date(2026, 11, 16, 1, 0, 0, 0, time.UTC), countries: []string{"MY"}, sectors: []string{"government", "defense"}},
		{key: id + "UGVwc2lDb0BJbmNlcHRpb24=", name: "PepsiCo", domain: "pepsico.com",
			attacker: "Inception", published: time.Date(2026, 11, 17, 8, 16, 23, 753000000, time.UTC), countries: []string{"US"}, sectors: []string{"agriculture", "food-beverage"}},
	} {
		w.link = w.key
		check(t, c, w)
	}
	if r := got[1].(*stix2.Report); r.Description != "Medical Practices Stolen data: 5 GB." {
		t.Errorf("description = %q, want the post's", r.Description)
	}
}

func TestPullFallsBackOrSkipsWhatIsMissing(t *testing.T) {
	t.Parallel()
	got, err := pull(t, []byte(`[
 {"victim":"Acme","domain":"HTTPS://WWW.Acme.example:8443/about","activity":"Technology","country":"mx","group":"lockbit","url":"",
  "attackdate":"","discovered":"2026-11-10T05:00:00+00:00","description":"Got in through CVE-2026-1111, and cve-2026-1111 again."},
 {"victim":"Acme S.A.","domain":"acme.example","activity":"Consumer Services","country":"Mexico","group":"akira","url":"https://www.ransomware.live/id/QWNtZQ==",
  "attackdate":"2026-11-11T05:00:00+00:00","discovered":"2026-11-11T06:00:00+00:00","description":""},
 {"victim":"No date","domain":"nodate.example","activity":"Technology","country":"US","group":"akira","url":"https://www.ransomware.live/id/bm9kYXRl",
  "attackdate":"soon","discovered":"","description":""},
 {"victim":" ","domain":"","activity":"","country":"","group":"akira","url":"https://www.ransomware.live/id/IA==",
  "attackdate":"2026-11-11T05:00:00+00:00","discovered":"","description":""}
]`))
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 4 {
		t.Fatalf("emitted %d objects, want 4: the posts without a date or a victim are skipped", len(got))
	}
	if got[0].GetID() != got[2].GetID() {
		t.Errorf("victims %s and %s, want one victim for two posts claiming one domain", got[0].GetID(), got[2].GetID())
	}
	c := roundTrip(t, got[:2])
	check(t, c, want{
		key: "Acme@lockbit", name: "Acme", domain: "acme.example", attacker: "lockbit",
		published: time.Date(2026, 11, 10, 5, 0, 0, 0, time.UTC), countries: []string{"MX"}, sectors: []string{"technology"},
		objects: []stix2.Identifier{stixext.VulnerabilityID("CVE-2026-1111")},
	})
	c = roundTrip(t, got[2:])
	check(t, c, want{
		key: "https://www.ransomware.live/id/QWNtZQ==", name: "Acme S.A.", domain: "acme.example", attacker: "akira",
		link: "https://www.ransomware.live/id/QWNtZQ==", published: time.Date(2026, 11, 11, 5, 0, 0, 0, time.UTC),
	})
}

func TestPullMintsTheSameIDsEachTime(t *testing.T) {
	t.Parallel()
	ids := func() []stix2.Identifier {
		got, err := pull(t, recentVictims)
		if err != nil {
			t.Fatal(err)
		}
		var ids []stix2.Identifier
		for _, o := range got {
			ids = append(ids, o.GetID())
		}
		return ids
	}
	if first, again := ids(), ids(); !slices.Equal(first, again) {
		t.Errorf("ids = %v, then %v; want the same", first, again)
	}
}

func TestPullFailsOnAnUnreadableList(t *testing.T) {
	t.Parallel()
	if _, err := pull(t, []byte(`{"error":"rate limited"}`)); err == nil {
		t.Error("err = nil, want a failure, not an empty Feed")
	}
}
