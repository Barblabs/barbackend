package kev_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"barbackend/internal/feeds/kev"
	"barbackend/internal/stixext"
)

const catalog = `{"catalogVersion":"2026.10.08","dateReleased":"2026-10-08T12:00:00.000Z","vulnerabilities":[
 {"cveID":"CVE-2020-0001","vendorProject":"a","product":"b","dateAdded":"not a date","shortDescription":"s","requiredAction":"r","dueDate":"2021-02-01","knownRansomwareCampaignUse":"Unknown"},
 {"cveID":"CVE-2025-32463","vendorProject":"Sudo","product":"Sudo","dateAdded":"2025-09-29","shortDescription":"chroot","requiredAction":"Apply mitigations","dueDate":"2025-10-20","knownRansomwareCampaignUse":"Unknown"}
]}`

func TestLookup(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(catalog)) }))
	t.Cleanup(srv.Close)
	adapter := kev.New(srv.Client(), srv.URL)

	v, err := adapter.Lookup(context.Background(), "CVE-2025-32463")
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := stixext.KEVOf(v)
	if !ok || entry.DateAdded != "2025-09-29" {
		t.Errorf("entry = %+v, %v; want the listed one, whatever is wrong with another entry", entry, ok)
	}

	v, err = adapter.Lookup(context.Background(), "CVE-2099-0001")
	if err != nil {
		t.Fatal(err)
	}
	if v != nil {
		t.Errorf("unlisted CVE = %+v, want nil", v)
	}
}
