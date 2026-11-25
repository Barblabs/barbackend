package findings_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"barbackend/internal/business"
	"barbackend/internal/findings"
	"barbackend/internal/inventory"
	"github.com/google/uuid"
)

// servicesWorld has open Findings on three Assets: a Critical one of nginx,
// which KEV lists, on "server pay" since 40 days ago, a Critical one of
// OpenSSL on "server hr" since 10 days ago, and a High one of nginx on
// "server mail".
func servicesWorld(t *testing.T) world {
	t.Helper()
	w := newWorld(t)
	w.sync(t,
		server(t, "pay", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0")),
		server(t, "hr", inventory.CriticalityHigh, app("OpenSSL", "openssl", "openssl", "1.1.1")),
		server(t, "mail", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0")),
	)
	w.handleNVD(t, nvdVulnerability(t, "CVE-2021-23017", "Analyzed", nginxBefore1201), nvdVulnerability(t, opensslCVE, "Analyzed", opensslBefore3))
	w.markKEV(t, "CVE-2021-23017")
	w.scoreHistory(t, "pay", critical(closesNow.AddDate(0, 0, -40)))
	w.scoreHistory(t, "hr", critical(closesNow.AddDate(0, 0, -10)))
	w.scoreHistory(t, "mail", high(closesNow.AddDate(0, 0, -5)))
	w.findings.SetNow(func() time.Time { return closesNow })
	return w
}

func (w world) serviceHealth(t *testing.T, services ...business.CriticalService) []findings.ServiceHealth {
	t.Helper()
	got, err := w.findings.CriticalServiceHealth(context.Background(), w.viewer(t), services)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func (w world) newsItem(t *testing.T, published time.Time, cves ...string) {
	t.Helper()
	w.exec(t, `
		INSERT INTO news_items (id, feed, kind, published_at, cve_ids, object, modified_at)
		VALUES ($1, 'rss', 'article', $2, $3, '{}', $2)`, "report--"+uuid.NewString(), published, cves)
}

func days(n int) *int { return &n }

func TestCriticalServiceHealthIsAtRiskForKEVWatchForCriticalAndClearOtherwise(t *testing.T) {
	t.Parallel()
	w := servicesWorld(t)

	got := w.serviceHealth(t,
		business.CriticalService{Name: "Payments", Assets: []string{"  SERVER PAY "}},
		business.CriticalService{Name: "Payroll", Assets: []string{"server hr"}},
		business.CriticalService{Name: "Mail", Assets: []string{"server mail", "mx-01"}},
	)

	want := []findings.ServiceHealth{
		{Name: "Payments", Status: findings.AtRisk, Open: findings.BandCounts{Critical: 1}, OldestCriticalDays: days(40), UnmatchedAssets: []string{}},
		{Name: "Payroll", Status: findings.Watch, Open: findings.BandCounts{Critical: 1}, OldestCriticalDays: days(10), UnmatchedAssets: []string{}},
		{Name: "Mail", Status: findings.Clear, Open: findings.BandCounts{High: 1}, UnmatchedAssets: []string{"mx-01"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("critical service health = %+v, want %+v", got, want)
	}
}

func TestACriticalNamedByANewsItemOfTheLastSevenDaysPutsItsServiceAtRisk(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name      string
		published time.Time
		status    findings.ServiceStatus
		inTheNews int
	}{
		{"six days ago", closesNow.AddDate(0, 0, -6), findings.AtRisk, 1},
		{"eight days ago", closesNow.AddDate(0, 0, -8), findings.Watch, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := servicesWorld(t)
			w.newsItem(t, tt.published, opensslCVE)

			got := w.serviceHealth(t, business.CriticalService{Name: "Payroll", Assets: []string{"server hr"}})[0]

			if got.Status != tt.status || got.InTheNews != tt.inTheNews {
				t.Errorf("status, in the news = %v, %d, want %v, %d", got.Status, got.InTheNews, tt.status, tt.inTheNews)
			}
		})
	}
}

func TestCriticalServiceHealthCountsEachFindingOfEveryActiveAssetOfAListedNameOnce(t *testing.T) {
	t.Parallel()
	w := servicesWorld(t)
	w.exec(t, `UPDATE assets SET name = 'server pay' WHERE record_id = 'hr'`)
	w.scoreHistory(t, "mail", critical(closesNow.AddDate(0, 0, -5)))
	w.exec(t, `UPDATE assets SET name = 'server gone', inactive_since = now() WHERE record_id = 'mail'`)

	got := w.serviceHealth(t, business.CriticalService{Name: "Payments", Assets: []string{"server pay", "Server Pay", "server gone"}})[0]

	if got.Open.Critical != 2 || *got.OldestCriticalDays != 40 || !reflect.DeepEqual(got.UnmatchedAssets, []string{"server gone"}) {
		t.Errorf("critical open, oldest critical days, unmatched = %d, %d, %v, want 2, 40, [server gone]", got.Open.Critical, *got.OldestCriticalDays, got.UnmatchedAssets)
	}
}
