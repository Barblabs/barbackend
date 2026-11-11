package nvd_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"barbackend/internal/feeds/nvd"
	"barbackend/internal/stixext"
)

// analyzed has CPE matches in the forms ADR 0015 reads: an exact version, a
// version with an update, an escaped version, a range, and an AND
// configuration whose condition (Oracle JDK) is not itself vulnerable.
const analyzed = `{"totalResults":1,"vulnerabilities":[{"cve":{
 "id":"CVE-2099-0001","published":"2099-01-01T00:00:00.000","lastModified":"2099-01-01T00:00:00.000","vulnStatus":"Analyzed",
 "descriptions":[{"lang":"en","value":"Several products in the forms NVD writes them."}],
 "configurations":[
  {"nodes":[{"cpeMatch":[
   {"vulnerable":true,"criteria":"cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*"},
   {"vulnerable":true,"criteria":"cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*"},
   {"vulnerable":true,"criteria":"cpe:2.3:o:cisco:ios:15.2\\(7\\)e:*:*:*:*:*:*:*"},
   {"vulnerable":true,"criteria":"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*","versionStartIncluding":"0.6.18","versionEndExcluding":"1.20.1"}]}]},
  {"operator":"AND","nodes":[
   {"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*","versionEndExcluding":"5.3.18"}]},
   {"cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*","versionStartIncluding":"9"}]}]}],
 "references":[]
}}]}`

func TestAffectedEntriesKeepVersionAndUpdate(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(analyzed))
	}))
	t.Cleanup(srv.Close)

	v, err := nvd.New(srv.Client(), srv.URL, "").Lookup(context.Background(), "CVE-2099-0001")
	if err != nil {
		t.Fatal(err)
	}
	record, ok := stixext.NVDOf(v)
	if !ok {
		t.Fatal("no nvd/1 extension")
	}
	type entry struct{ vendor, product, version, update, start, end string }
	want := []entry{
		{"tukaani", "xz", "5.6.1", "*", "", ""},
		{"apache", "log4j", "2.0", "beta9", "", ""},
		{"cisco", "ios", "15.2(7)e", "*", "", ""},
		{"f5", "nginx", "*", "*", "0.6.18", "1.20.1"},
		{"vmware", "spring_framework", "*", "*", "", "5.3.18"},
	}
	if len(record.Affected) != len(want) {
		t.Fatalf("affected = %+v, want %d entries", record.Affected, len(want))
	}
	for i, a := range record.Affected {
		got := entry{a.Vendor, a.Product, a.Version, a.Update, a.VersionStartIncluding, a.VersionEndExcluding}
		if got != want[i] {
			t.Errorf("affected[%d] = %+v, want %+v", i, got, want[i])
		}
	}
}
