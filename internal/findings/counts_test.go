package findings_test

import (
	"context"
	"errors"
	"testing"

	"barbackend/internal/findings"
	"barbackend/internal/inventory"
	"barbackend/internal/stixext"
)

const opensslCVE = "CVE-2022-0778"

var opensslBefore3 = stixext.Affected{Vendor: "openssl", Product: "openssl", Version: "*", Update: "*", VersionStartIncluding: "1.0.2", VersionEndExcluding: "3.0.0"}

// countedWorld has three open Findings: Critical nginx and Medium OpenSSL on
// the Internet-facing, High-Criticality "a", and High nginx on "b", of Low
// Criticality and Unknown Exposure. KEV lists nginx's CVE.
func countedWorld(t *testing.T) world {
	t.Helper()
	w := newWorld(t)
	w.sync(t,
		server(t, "a", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0"), app("OpenSSL", "openssl", "openssl", "1.1.1")),
		server(t, "b", inventory.CriticalityLow, app("Nginx", "f5", "nginx", "1.18.0")),
	)
	w.handleNVD(t, nvdVulnerability(t, "CVE-2021-23017", "Analyzed", nginxBefore1201), nvdVulnerability(t, opensslCVE, "Analyzed", opensslBefore3))
	w.declareExposure(t, "a", inventory.InternetFacing)
	w.setScore(t, "a", "CVE-2021-23017", 0.75)
	w.setScore(t, "a", opensslCVE, 0.25)
	w.setScore(t, "b", "CVE-2021-23017", 0.45)
	w.exec(t, `UPDATE vulnerabilities SET object = jsonb_set(object, ARRAY['extensions', $1::text], '{"extension_type":"property-extension"}') WHERE cve_id = $2`,
		string(stixext.KEVDefinitionID), "CVE-2021-23017")
	return w
}

func TestSummaryCountsOpenFindingsByBandKEVAndCriticalInternetFacing(t *testing.T) {
	t.Parallel()
	w := countedWorld(t)

	sum, err := w.findings.Summary(context.Background(), w.viewer(t))
	if err != nil {
		t.Fatal(err)
	}

	want := findings.Summary{Bands: findings.BandCounts{Critical: 1, High: 1, Medium: 1}, KEV: 2, CriticalInternetFacing: 1}
	if sum != want {
		t.Errorf("summary = %+v, want %+v", sum, want)
	}
}

func TestBreakdownKeepsEveryExposureAndCriticality(t *testing.T) {
	t.Parallel()
	w := countedWorld(t)

	exposure, err := w.findings.Breakdown(context.Background(), w.viewer(t), findings.ByExposure)
	if err != nil {
		t.Fatal(err)
	}
	criticality, err := w.findings.Breakdown(context.Background(), w.viewer(t), findings.ByCriticality)
	if err != nil {
		t.Fatal(err)
	}
	area, err := w.findings.Breakdown(context.Background(), w.viewer(t), findings.ByArea)
	if err != nil {
		t.Fatal(err)
	}

	wantExposure := []findings.Group{
		{Exposure: inventory.InternetFacing, Bands: findings.BandCounts{Critical: 1, Medium: 1}},
		{Exposure: inventory.Internal},
		{Exposure: inventory.ExposureUnknown, Bands: findings.BandCounts{High: 1}},
	}
	wantCriticality := []findings.Group{
		{Criticality: inventory.CriticalityHigh, Bands: findings.BandCounts{Critical: 1, Medium: 1}},
		{Criticality: inventory.CriticalityMedium},
		{Criticality: inventory.CriticalityLow, Bands: findings.BandCounts{High: 1}},
		{Criticality: inventory.CriticalityUnknown},
	}
	assertGroups(t, "exposure", exposure, wantExposure)
	assertGroups(t, "criticality", criticality, wantCriticality)
	if len(area) != 1 || area[0].Area != nil || area[0].Bands.Total() != 3 {
		t.Errorf("by area = %+v, want one group of the three Findings in no Area", area)
	}
}

func assertGroups(t *testing.T, by string, got, want []findings.Group) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("by %s = %+v, want %+v", by, got, want)
	}
	for i := range want {
		if got[i].Exposure != want[i].Exposure || got[i].Criticality != want[i].Criticality || got[i].Bands != want[i].Bands {
			t.Errorf("by %s, group %d = %+v, want %+v", by, i, got[i], want[i])
		}
	}
}

func TestTopPutsTheMostSevereComponentsAndCVEsFirst(t *testing.T) {
	t.Parallel()
	w := countedWorld(t)

	top, err := w.findings.Top(context.Background(), w.viewer(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	first, err := w.findings.Top(context.Background(), w.viewer(t), 1)
	if err != nil {
		t.Fatal(err)
	}

	if len(top.Components) != 2 || len(top.CVEs) != 2 {
		t.Fatalf("top = %+v, want two components and two CVEs", top)
	}
	nginx := top.Components[0]
	if nginx.Product != (inventory.Product{Vendor: "f5", Name: "nginx"}) || nginx.Version != "1.18.0" || nginx.Assets != 2 || nginx.Bands != (findings.BandCounts{Critical: 1, High: 1}) {
		t.Errorf("first component = %+v, want nginx 1.18.0 on both Assets", nginx)
	}
	if cve := top.CVEs[0]; cve.CVE != "CVE-2021-23017" || !cve.KEV || cve.Assets != 2 || top.CVEs[1].CVE != opensslCVE || top.CVEs[1].KEV {
		t.Errorf("CVEs = %+v, want nginx's, in KEV, then OpenSSL's", top.CVEs)
	}
	if len(first.Components) != 1 || len(first.CVEs) != 1 {
		t.Errorf("top 1 = %+v, want one of each", first)
	}
}

func TestCountsRefuseALimitOrGroupingOutOfRange(t *testing.T) {
	t.Parallel()
	w := newWorld(t)

	if _, err := w.findings.Top(context.Background(), w.viewer(t), findings.MaxTopLimit+1); !errors.Is(err, findings.ErrInvalidCount) {
		t.Errorf("top %d: err = %v, want ErrInvalidCount", findings.MaxTopLimit+1, err)
	}
	if _, err := w.findings.Breakdown(context.Background(), w.viewer(t), 0); !errors.Is(err, findings.ErrInvalidCount) {
		t.Errorf("grouping 0: err = %v, want ErrInvalidCount", err)
	}
}

// setScore makes every Score of the record's Finding of cve one of Scoring
// Model 3 with that value, which has Score Bands.
func (w world) setScore(t *testing.T, record, cve string, value float64) {
	t.Helper()
	w.exec(t, `UPDATE finding_scores SET model = 3, value = $1 WHERE finding_id = (SELECT id FROM findings WHERE record_id = $2 AND cve_id = $3)`, value, record, cve)
}
