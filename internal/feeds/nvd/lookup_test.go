package nvd_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"barbackend/internal/feeds/nvd"
	"barbackend/internal/stixext"
)

// deferred has the shape of CVE-2025-1094 today: NVD did not analyze it, so
// it has no configurations, and relays what the CVE's numbering authority lists.
const deferred = `{"totalResults":1,"vulnerabilities":[{"cve":{
 "id":"CVE-2025-1094","published":"2025-02-13T13:15:09.650","lastModified":"2026-06-17T08:38:22.263","vulnStatus":"Deferred",
 "descriptions":[{"lang":"en","value":"Improper neutralization of quoting syntax in PostgreSQL libpq."}],
 "affected":[{"source":"f86ef6dc","affectedData":[{"vendor":"n/a","product":"PostgreSQL","defaultStatus":"unaffected","versions":[
   {"version":"15","lessThan":"15.11","versionType":"rpm","status":"affected"}]}]}],
 "metrics":{"cvssMetricV31":[{"source":"f86ef6dc","type":"Secondary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N","baseScore":8.1}}]},
 "references":[{"url":"https://www.postgresql.org/support/security/CVE-2025-1094/","source":"f86ef6dc"}]
}}]}`

func TestLookup(t *testing.T) {
	t.Parallel()
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		_, _ = w.Write([]byte(deferred))
	}))
	t.Cleanup(srv.Close)

	v, err := nvd.New(srv.Client(), srv.URL, "").Lookup(context.Background(), "CVE-2025-1094")
	if err != nil {
		t.Fatal(err)
	}
	if query != "cveId=CVE-2025-1094" {
		t.Errorf("query = %q", query)
	}
	record, ok := stixext.NVDOf(v)
	if !ok || record.VulnStatus != "Deferred" {
		t.Fatalf("record = %+v, %v", record, ok)
	}
	if len(record.CNAAffected) != 1 || record.CNAAffected[0].Product != "PostgreSQL" || record.CNAAffected[0].Versions[0].LessThan != "15.11" {
		t.Errorf("cna affected = %+v, want PostgreSQL before 15.11", record.CNAAffected)
	}
}

func TestLookupOfACVENVDDoesNotHave(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
	}))
	t.Cleanup(srv.Close)

	v, err := nvd.New(srv.Client(), srv.URL, "").Lookup(context.Background(), "CVE-2099-0001")
	if err != nil {
		t.Fatal(err)
	}
	if v != nil {
		t.Errorf("v = %+v, want nil", v)
	}
}
