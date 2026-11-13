package findings_test

import (
	"context"
	"slices"
	"testing"

	"barbackend/internal/inventory"
	"barbackend/internal/stixext"
)

func TestHandleNVDOpensAScoredFindingOnEachAffectedAsset(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.sync(t,
		server(t, "payments", inventory.CriticalityHigh, app("Nginx of payments", "F5", "Nginx", "1.18.0")),
		server(t, "lab", inventory.CriticalityLow, app("Nginx of the lab", "f5", "nginx", "1.20.1")),
	)

	w.handleNVD(t, nvdVulnerability(t, "CVE-2021-23017", "Analyzed", nginxBefore1201))

	f := w.mustFinding(t, "payments", "CVE-2021-23017")
	if !f.open || f.version != "1.18.0" || f.flags != 0 {
		t.Errorf("payments finding = %+v, want open at 1.18.0 and certain", f)
	}
	if _, ok := w.finding(t, "lab", "CVE-2021-23017"); ok {
		t.Error("lab runs the fixed 1.20.1 and got a finding")
	}
	_, _, gaps, scores := w.latestScore(t, f.id)
	if scores != 1 || !slices.Equal(gaps, []string{"epss_pending", "kev_stale", "exposure_undeclared", "lifecycle_unknown"}) {
		t.Errorf("score = %d scores with gaps %v, want one, waiting for EPSS and KEV, exposure undeclared, lifecycle unknown", scores, gaps)
	}
}

func TestHandleNVDStoresNothingWithoutAMatch(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.sync(t, server(t, "payments", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0")))

	w.handleNVD(t, nvdVulnerability(t, "CVE-2024-3094", "Analyzed", stixext.Affected{Vendor: "tukaani", Product: "xz", Version: "5.6.1", Update: "*"}))

	if n := w.count(t, `SELECT count(*) FROM vulnerabilities`); n != 0 {
		t.Errorf("stored vulnerabilities = %d, want none: no Asset runs xz", n)
	}
}

func TestHandleNVDClosesAFindingThatNoLongerMatches(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.sync(t, server(t, "payments", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0")))
	w.handleNVD(t, nvdVulnerability(t, "CVE-2021-23017", "Analyzed", nginxBefore1201))

	narrowed := nginxBefore1201
	narrowed.VersionEndExcluding = "1.16.0"
	w.handleNVD(t, nvdVulnerability(t, "CVE-2021-23017", "Modified", narrowed))

	if f := w.mustFinding(t, "payments", "CVE-2021-23017"); f.open || f.closeReason != "no_longer_affected" {
		t.Errorf("finding = %+v, want closed no_longer_affected after NVD narrowed the range", f)
	}
}

func TestHandleNVDClosesTheFindingsOfARejectedCVE(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.sync(t, server(t, "payments", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0")))
	w.handleNVD(t, nvdVulnerability(t, "CVE-2021-23017", "Analyzed", nginxBefore1201))

	w.handleNVD(t, nvdVulnerability(t, "CVE-2021-23017", "Rejected", nginxBefore1201))

	if f := w.mustFinding(t, "payments", "CVE-2021-23017"); f.open || f.closeReason != "vulnerability_rejected" {
		t.Errorf("finding = %+v, want closed vulnerability_rejected", f)
	}
}

func TestHandleNVDKeepsTheMostCertainOfTwoInstallations(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.sync(t, server(t, "payments", inventory.CriticalityHigh,
		app("Nginx of the old portal", "f5", "nginx", "latest"),
		app("Nginx of payments", "f5", "nginx", "1.18.0"),
	))

	w.handleNVD(t, nvdVulnerability(t, "CVE-2021-23017", "Analyzed", nginxBefore1201))

	if n := w.count(t, `SELECT count(*) FROM findings`); n != 1 {
		t.Fatalf("findings = %d, want one for both installations", n)
	}
	if f := w.mustFinding(t, "payments", "CVE-2021-23017"); f.version != "1.18.0" || f.flags != 0 {
		t.Errorf("finding = %+v, want the certain match at 1.18.0", f)
	}
}

func TestHandleNVDGoesOnAfterAnObjectItCannotUse(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.sync(t, server(t, "payments", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0")))

	err := w.findings.HandleNVD(context.Background(), batch(
		nvdVulnerability(t, "not-a-cve", "Analyzed", nginxBefore1201),
		nvdVulnerability(t, "CVE-2021-23017", "Analyzed", nginxBefore1201),
	))

	if err != nil {
		t.Fatalf("HandleNVD = %v, want the batch handled", err)
	}
	if _, ok := w.finding(t, "payments", "CVE-2021-23017"); !ok {
		t.Error("the valid CVE after the odd object was not matched")
	}
}
