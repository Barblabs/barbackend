package assessment_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"barbackend/internal/assessment"
	"barbackend/internal/inventory"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

func TestDossierScoresTheFinding(t *testing.T) {
	t.Parallel()
	d := dossier(t)
	// S = 0.3*0.81 + 0.3*0.9003 + 0.4*1 = 0.9131, on High Criticality and Unknown Exposure.
	if d.Score.Value != 0.9131 || d.Score.ScoringModel != 1 {
		t.Errorf("score = %+v", d.Score)
	}
	if !slices.Equal(d.Score.DataGaps, []string{"exposure_undeclared"}) {
		t.Errorf("gaps = %v", d.Score.DataGaps)
	}
	if d.Description == "" || !strings.Contains(d.Description, "PostgreSQL") {
		t.Errorf("description = %q, want NVD's over KEV's", d.Description)
	}
	if len(d.NVD.References) != 1 || d.NVD.References[0] != advisory {
		t.Errorf("references = %v", d.NVD.References)
	}
}

func TestDossierPrefersTheNewestPrimaryCVSS(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		metrics []stixext.CVSS
		alpha   float64
	}{
		{"newest primary", []stixext.CVSS{{Version: "2.0", BaseScore: 5, Type: "Primary"}, {Version: "3.1", BaseScore: 9, Type: "Primary"}, {Version: "4.0", BaseScore: 2, Type: "Secondary"}}, 0.9},
		{"secondary without primary", []stixext.CVSS{{Version: "3.1", BaseScore: 7, Type: "Secondary"}}, 0.7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d, err := assessment.NewDossier(finding, cve, newAsset(t, inventory.CriticalityHigh), "PostgreSQL", assessment.Feeds{NVD: nvdRecord(t, tt.metrics...)})
			if err != nil {
				t.Fatal(err)
			}
			if d.Score.Alpha != tt.alpha || slices.Contains(d.Score.DataGaps, "cvss_estimated") {
				t.Errorf("score = %+v, want alpha %v measured", d.Score, tt.alpha)
			}
		})
	}
}

func TestDossierTurnsMissingInputsIntoDataGaps(t *testing.T) {
	t.Parallel()
	d, err := assessment.NewDossier(finding, cve, newAsset(t, inventory.CriticalityUnknown), "PostgreSQL", assessment.Feeds{Unavailable: []string{assessment.FeedKEV, assessment.FeedNVD}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cvss_estimated", "epss_pending", "kev_stale", "criticality_unknown", "exposure_undeclared"}
	if !slices.Equal(d.Score.DataGaps, want) {
		t.Errorf("gaps = %v, want %v", d.Score.DataGaps, want)
	}
	if !slices.Equal(d.UnavailableFeeds, []string{assessment.FeedKEV, assessment.FeedNVD}) || d.Asset.Criticality != "unknown" || d.Asset.Exposure != "unknown" {
		t.Errorf("dossier = %+v", d)
	}
}

func TestDossierTreatsAnOutOfRangeFeedAsUnavailable(t *testing.T) {
	t.Parallel()
	epss := func(probability float64) *stix2.Vulnerability {
		return vulnerability(t, cve, "", stixext.EPSSDefinitionID, stixext.EPSS{Probability: probability})
	}
	tests := []struct {
		name string
		in   assessment.Feeds
		feed string
		gap  string
	}{
		{"EPSS above 1", assessment.Feeds{EPSS: epss(1.5)}, assessment.FeedEPSS, "epss_pending"},
		{"CVSS above 10", assessment.Feeds{NVD: nvdRecord(t, stixext.CVSS{Version: "3.1", BaseScore: 11, Type: "Primary"})}, assessment.FeedNVD, "cvss_estimated"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d, err := assessment.NewDossier(finding, cve, newAsset(t, inventory.CriticalityHigh), "PostgreSQL", tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(d.UnavailableFeeds, []string{tt.feed}) || !slices.Contains(d.Score.DataGaps, tt.gap) {
				t.Errorf("dossier = %+v, want %s unavailable and %s", d, tt.feed, tt.gap)
			}
		})
	}
}

func TestNewDossierTakesTheComponentByName(t *testing.T) {
	t.Parallel()
	d := dossier(t)
	if d.Finding != finding || d.Component != (assessment.Software{Role: "application", Name: "PostgreSQL", Version: "15.6"}) {
		t.Errorf("finding = %q, component = %+v", d.Finding, d.Component)
	}
	_, err := assessment.NewDossier(finding, cve, newAsset(t, inventory.CriticalityHigh), "MySQL", assessment.Feeds{})
	if !errors.Is(err, assessment.ErrInvalidDossier) {
		t.Errorf("err = %v, want ErrInvalidDossier for a component the Asset does not run", err)
	}
}

func TestValidateRejectsADossierBuiltWrong(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		change func(*assessment.Dossier)
		want   string
	}{
		{"blank finding", func(d *assessment.Dossier) { d.Finding = " " }, "finding is blank"},
		{"lower-case CVE", func(d *assessment.Dossier) { d.CVE = "cve-2025-1094" }, "cve"},
		{"not a CVE", func(d *assessment.Dossier) { d.CVE = "GHSA-1234" }, "cve"},
		{"blank asset", func(d *assessment.Dossier) { d.Asset.Name = "" }, "asset name"},
		{"unknown criticality code", func(d *assessment.Dossier) { d.Asset.Criticality = "critical" }, "criticality"},
		{"unknown exposure code", func(d *assessment.Dossier) { d.Asset.Exposure = "public" }, "exposure"},
		{"unknown kind", func(d *assessment.Dossier) { d.Asset.Kind = "toaster" }, "kind"},
		{"unknown role", func(d *assessment.Dossier) { d.Asset.Software[0].Role = "x" }, "role"},
		{"blank data gap", func(d *assessment.Dossier) { d.Score.DataGaps = []string{""} }, "data gap"},
		{"unknown feed", func(d *assessment.Dossier) { d.UnavailableFeeds = []string{"whatever"} }, "unavailable feed"},
		{"component the Asset does not run", func(d *assessment.Dossier) { d.Component.Version = "16.0" }, "component"},
		{"score above 1", func(d *assessment.Dossier) { d.Score.Value = 1.2 }, "score"},
		{"no scoring model", func(d *assessment.Dossier) { d.Score.ScoringModel = 0 }, "score"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := dossier(t)
			tt.change(&d)
			err := d.Validate()
			if !errors.Is(err, assessment.ErrInvalidDossier) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want ErrInvalidDossier about %q", err, tt.want)
			}
		})
	}
	if err := dossier(t).Validate(); err != nil {
		t.Errorf("valid dossier: %v", err)
	}
}

func TestBriefLeavesOutWhatOnlyAnActionPlanNeeds(t *testing.T) {
	t.Parallel()
	b := dossier(t).Brief()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, left := range []string{advisory, "cna_affected", "Ubuntu Server"} {
		if strings.Contains(string(raw), left) {
			t.Errorf("brief holds %q: %s", left, raw)
		}
	}
	if b.Finding != finding || b.Asset.Criticality != "high" || b.Component.Version != "15.6" || b.NVD == nil || len(b.NVD.CVSS) != 1 || b.KEV == nil || b.EPSS == nil {
		t.Errorf("brief = %+v", b)
	}
}

func TestDossierLeavesOutTheAssetOwner(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(dossier(t))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "owner@example.com") {
		t.Errorf("dossier holds the Asset Owner: %s", raw)
	}
}
