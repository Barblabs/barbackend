package nvd_test

import (
	"testing"
	"time"

	"barbackend/internal/stixext"
)

// deferred has the shape of CVE-2025-1094 today: NVD did not analyze it, so
// it has no configurations, and relays what the CVE's numbering authority
// lists. The second CVE has no CVE ID and is skipped.
const deferred = `{"totalResults":2,"vulnerabilities":[{"cve":{
 "id":"CVE-2025-1094","published":"2025-02-13T13:15:09.650","lastModified":"2026-06-17T08:38:22.263","vulnStatus":"Deferred",
 "descriptions":[{"lang":"en","value":"Improper neutralization of quoting syntax in PostgreSQL libpq."}],
 "affected":[{"source":"f86ef6dc","affectedData":[{"vendor":"n/a","product":"PostgreSQL","defaultStatus":"unaffected","versions":[
   {"version":"15","lessThan":"15.11","versionType":"rpm","status":"affected"}]}]}],
 "metrics":{"cvssMetricV31":[{"source":"f86ef6dc","type":"Secondary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N","baseScore":8.1}}]},
 "references":[{"url":"https://www.postgresql.org/support/security/CVE-2025-1094/","source":"f86ef6dc"}]
}},{"cve":{"id":"GHSA-0000-0000-0000","published":"2025-02-13T13:15:09.650","lastModified":"2026-06-17T08:38:22.263"}}]}`

func TestPullEmitsWhatTheNumberingAuthorityListsForAnUnanalyzedCVE(t *testing.T) {
	t.Parallel()
	got, _ := pull(t, deferred)

	if len(got) != 1 {
		t.Fatalf("emitted %d vulnerabilities, want CVE-2025-1094 alone", len(got))
	}
	record, ok := stixext.NVDOf(got[0])
	if !ok || record.VulnStatus != "Deferred" {
		t.Fatalf("record = %+v, %v", record, ok)
	}
	if len(record.CNAAffected) != 1 || record.CNAAffected[0].Product != "PostgreSQL" || record.CNAAffected[0].Versions[0].LessThan != "15.11" {
		t.Errorf("cna affected = %+v, want PostgreSQL before 15.11", record.CNAAffected)
	}
	if len(record.CVSS) != 1 || record.CVSS[0].BaseScore != 8.1 {
		t.Errorf("cvss = %+v, want the 3.1 score of 8.1", record.CVSS)
	}
}

func TestPullAsksForTheCVEsModifiedInTheLastDay(t *testing.T) {
	t.Parallel()
	_, query := pull(t, `{"totalResults":0,"vulnerabilities":[]}`)

	const layout = "2006-01-02T15:04:05.000Z07:00"
	start, err := time.Parse(layout, query.Get("lastModStartDate"))
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.Parse(layout, query.Get("lastModEndDate"))
	if err != nil {
		t.Fatal(err)
	}
	if end.Sub(start) != 24*time.Hour || time.Since(end) > time.Minute {
		t.Errorf("window = %v to %v, want the 24 hours up to now", start, end)
	}
}
