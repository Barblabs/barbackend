package kev_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"barbackend/internal/feeds/kev"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

func pull(t *testing.T, catalog string) ([]*stix2.Vulnerability, error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(catalog)) }))
	t.Cleanup(srv.Close)
	var got []*stix2.Vulnerability
	err := kev.New(srv.Client(), srv.URL).Pull(context.Background(), func(o stix2.STIXObject) error {
		got = append(got, o.(*stix2.Vulnerability))
		return nil
	})
	return got, err
}

func TestPullEmitsEachCVEOfTheCatalog(t *testing.T) {
	t.Parallel()
	got, err := pull(t, `{"catalogVersion":"2026.10.08","dateReleased":"2026-10-08T12:00:00.000Z","vulnerabilities":[
 {"cveID":"not a CVE","dateAdded":"2025-09-29","dueDate":"2025-10-20"},
 {"cveID":"CVE-2025-32463","vendorProject":"Sudo","product":"Sudo","dateAdded":"2025-09-29","shortDescription":"chroot","requiredAction":"Apply mitigations","dueDate":"2025-10-20","knownRansomwareCampaignUse":"Unknown"}
]}`)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 1 {
		t.Fatalf("emitted %d vulnerabilities, want CVE-2025-32463 alone", len(got))
	}
	entry, ok := stixext.KEVOf(got[0])
	want := stixext.NewKEV(stixext.KEV{
		DateAdded: "2025-09-29", DueDate: "2025-10-20", RequiredAction: "Apply mitigations", KnownRansomwareCampaignUse: "Unknown",
		VendorProject: "Sudo", Product: "Sudo", CatalogVersion: "2026.10.08", CatalogReleased: "2026-10-08T12:00:00Z",
	})
	if !ok || entry != want {
		t.Errorf("entry = %+v, %v; want %+v", entry, ok, want)
	}
}

func TestPullFailsOnAnUnreadableDate(t *testing.T) {
	t.Parallel()
	_, err := pull(t, `{"catalogVersion":"2026.10.08","dateReleased":"2026-10-08T12:00:00.000Z","vulnerabilities":[
 {"cveID":"CVE-2020-0001","dateAdded":"not a date","dueDate":"2021-02-01"}
]}`)
	if err == nil {
		t.Error("err = nil, want a failure, not an entry without its date")
	}
}
