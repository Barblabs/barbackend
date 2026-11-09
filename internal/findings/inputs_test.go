package findings_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"barbackend/internal/findings"
	"barbackend/internal/inventory"
	"barbackend/internal/scoring"
)

// matchedPayments is a world whose payments server has an open Finding of
// CVE-2021-23017.
func matchedPayments(t *testing.T) (world, storedFinding) {
	t.Helper()
	w := newWorld(t)
	w.sync(t, server(t, "payments", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0")))
	w.handleNVD(t, nvdVulnerability(t, "CVE-2021-23017", "Analyzed", nginxBefore1201))
	return w, w.mustFinding(t, "payments", "CVE-2021-23017")
}

func TestHandleKEVRescoresTheFindingsOfAListedCVE(t *testing.T) {
	t.Parallel()
	w, f := matchedPayments(t)

	if err := w.findings.HandleKEV(context.Background(), batch(kevListing(t, "CVE-2021-23017"), kevListing(t, "CVE-2099-0001"))); err != nil {
		t.Fatal(err)
	}

	gamma, _, gaps, scores := w.latestScore(t, f.id)
	if gamma != 1 || scores != 2 || slices.Contains(gaps, "kev_stale") {
		t.Errorf("latest score: gamma %v, %d scores, gaps %v; want listed, rescored, KEV no longer stale", gamma, scores, gaps)
	}
	if n := w.count(t, `SELECT count(*) FROM vulnerabilities`); n != 1 {
		t.Errorf("stored vulnerabilities = %d, want only the matched CVE: a listing no Finding cares about is not kept", n)
	}
}

func TestHandleEPSSRescoresOnlyStoredCVEs(t *testing.T) {
	t.Parallel()
	w, f := matchedPayments(t)

	if err := w.findings.HandleEPSS(context.Background(), batch(epssScore(t, "CVE-2021-23017", 0.9), epssScore(t, "CVE-2099-0001", 0.5))); err != nil {
		t.Fatal(err)
	}

	_, beta, gaps, scores := w.latestScore(t, f.id)
	if beta != 0.9 || scores != 2 || slices.Contains(gaps, "epss_pending") {
		t.Errorf("latest score: beta %v, %d scores, gaps %v; want EPSS 0.9, rescored, no longer pending", beta, scores, gaps)
	}
	if n := w.count(t, `SELECT count(*) FROM vulnerabilities`); n != 1 {
		t.Errorf("stored vulnerabilities = %d, want only the matched CVE", n)
	}
}

func TestHandleEPSSStoresNoScoreThatDidNotChange(t *testing.T) {
	t.Parallel()
	w, f := matchedPayments(t)
	for range 2 {
		if err := w.findings.HandleEPSS(context.Background(), batch(epssScore(t, "CVE-2021-23017", 0.9))); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, scores := w.latestScore(t, f.id); scores != 2 {
		t.Errorf("scores = %d, want the first and the one EPSS changed, not a copy for the same EPSS", scores)
	}
}

func TestAKEVCatalogOlderThanItsMaximumAgeIsStale(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.findings = findings.New(w.db, scoring.Model1, time.Nanosecond)
	w.sync(t, server(t, "payments", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0")))
	if err := w.findings.HandleKEV(context.Background(), batch(kevListing(t, "CVE-2099-0001"))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)

	w.handleNVD(t, nvdVulnerability(t, "CVE-2021-23017", "Analyzed", nginxBefore1201))

	f := w.mustFinding(t, "payments", "CVE-2021-23017")
	if _, _, gaps, _ := w.latestScore(t, f.id); !slices.Contains(gaps, "kev_stale") {
		t.Errorf("gaps = %v, want kev_stale once the catalog is older than its maximum age", gaps)
	}
}
