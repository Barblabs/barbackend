package assessment_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"barbackend/internal/assessment"
	"barbackend/internal/inventory"
	"barbackend/internal/scoring"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

func TestNewDossierReadsTheStoredFinding(t *testing.T) {
	t.Parallel()
	d := dossier(t)
	if d.Finding != finding || d.CVE != cve || !strings.Contains(d.Description, "PostgreSQL") {
		t.Errorf("dossier = %+v", d)
	}
	want := assessment.Score{
		ScoringModel: 1, Value: 0.9131, Alpha: 0.81, Beta: 0.9003, Gamma: 1, Vulnerability: 0.9131,
		CriticalityMultiplier: 1, ExposureMultiplier: 1, DataGaps: []string{"exposure_undeclared"},
	}
	if d.Score.Value != want.Value || d.Score.Alpha != want.Alpha || !slices.Equal(d.Score.DataGaps, want.DataGaps) {
		t.Errorf("score = %+v, want the stored one rounded, %+v", d.Score, want)
	}
	if d.KEV == nil || d.KEV.DateAdded != "2025-09-29" || d.EPSS == nil || d.EPSS.Probability != 0.9003 || len(d.NVD.References) != 1 || d.NVD.References[0] != advisory {
		t.Errorf("feeds = kev %+v, epss %+v, nvd %+v", d.KEV, d.EPSS, d.NVD)
	}
	if len(d.UnavailableFeeds) != 0 {
		t.Errorf("unavailable = %v, want none", d.UnavailableFeeds)
	}
	if len(d.Advisories) != 1 || d.Labeling.Outcome != assessment.LabelingLabeled || len(d.Techniques) != 1 || d.Techniques[0].Mitigations[0].AttackID != "M1051" {
		t.Errorf("threats = %+v %+v %+v", d.Advisories, d.Labeling, d.Techniques)
	}
	if len(d.Asset.CriticalServices) != 1 || d.Asset.CriticalServices[0].Impact != "critical" {
		t.Errorf("critical services = %+v", d.Asset.CriticalServices)
	}
}

func TestNewDossierMakesKEVUnavailableWhenTheScoreFoundItStale(t *testing.T) {
	t.Parallel()
	s := stored(t)
	s.Score.Gaps = []scoring.DataGap{scoring.KEVStale, scoring.ExposureUndeclared}

	d, err := assessment.NewDossier(s)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(d.UnavailableFeeds, []string{assessment.FeedKEV}) || d.KEV != nil {
		t.Errorf("unavailable = %v, kev = %+v, want KEV unknown, not listed", d.UnavailableFeeds, d.KEV)
	}
}

func TestNewDossierTreatsAnOutOfRangeFeedAsUnavailable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		extensions map[stix2.Identifier]any
		feed       string
	}{
		{"EPSS above 1", map[stix2.Identifier]any{stixext.EPSSDefinitionID: stixext.NewEPSS(stixext.EPSS{Probability: 1.5})}, assessment.FeedEPSS},
		{"CVSS above 10", map[stix2.Identifier]any{stixext.NVDDefinitionID: nvdExtension(stixext.CVSS{Version: "3.1", BaseScore: 11, Type: "Primary"})}, assessment.FeedNVD},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := stored(t)
			s.Vulnerability = vulnerability(t, cve, "PostgreSQL is affected.", tt.extensions)

			d, err := assessment.NewDossier(s)
			if err != nil {
				t.Fatal(err)
			}

			if !slices.Equal(d.UnavailableFeeds, []string{tt.feed}) || d.EPSS != nil || d.NVD != nil {
				t.Errorf("dossier = %+v, want %s unavailable", d, tt.feed)
			}
		})
	}
}

func TestNewDossierTakesTheComponentTheFindingWasMatchedOn(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, component, version string
		want                     assessment.Software
	}{
		{"same name and version", "postgresql", "15.6", assessment.Software{Role: "application", Name: "PostgreSQL", Version: "15.6"}},
		{"a version a Sync changed since", "PostgreSQL", "15.5", assessment.Software{Role: "application", Name: "PostgreSQL", Version: "15.6"}},
		{"one the Asset no longer runs", "MySQL", "8.0", assessment.Software{Name: "MySQL", Version: "8.0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := stored(t)
			s.ComponentName, s.ComponentVersion = tt.component, tt.version

			d, err := assessment.NewDossier(s)
			if err != nil {
				t.Fatal(err)
			}

			if d.Component != tt.want {
				t.Errorf("component = %+v, want %+v", d.Component, tt.want)
			}
		})
	}
}

func TestNewAdvisoryIsPlainText(t *testing.T) {
	t.Parallel()
	a := assessment.NewAdvisory("aws", time.Date(2025, 2, 13, 23, 0, 0, 0, time.UTC), "<b>PostgreSQL</b> &amp; RDS", "<p>Apply\n\n  the   fix.</p>")
	if a != (assessment.Advisory{Title: "PostgreSQL & RDS", Published: "2025-02-13", Feed: "aws", Description: "Apply\nthe fix."}) {
		t.Errorf("advisory = %+v", a)
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
		{"blank component", func(d *assessment.Dossier) { d.Component.Name = " " }, "component"},
		{"score above 1", func(d *assessment.Dossier) { d.Score.Value = 1.2 }, "score"},
		{"no scoring model", func(d *assessment.Dossier) { d.Score.ScoringModel = 0 }, "score"},
		{"unknown labeling outcome", func(d *assessment.Dossier) { d.Labeling.Outcome = "" }, "labeling outcome"},
		{"techniques of a labeling that failed", func(d *assessment.Dossier) { d.Labeling.Outcome = assessment.LabelingFailed }, `labeling is "failed"`},
		{"more techniques than the Cartógrafo gives", func(d *assessment.Dossier) {
			for range assessment.MaxTechniques {
				d.Techniques = append(d.Techniques, d.Techniques[0])
			}
		}, "more than 5"},
		{"a technique that is not an ATT&CK id", func(d *assessment.Dossier) { d.Techniques[0].AttackID = "M1051" }, "technique"},
		{"a technique of no known role", func(d *assessment.Dossier) { d.Techniques[0].Role = "pivot" }, "technique"},
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
	for _, left := range []string{advisory, "cna_affected", "Ubuntu Server", "M1051", "applied the fix", "inyección", "PostgreSQL before 15.11 is affected\""} {
		if strings.Contains(string(raw), left) {
			t.Errorf("brief holds %q: %s", left, raw)
		}
	}
	if b.Finding != finding || b.Asset.Criticality != "high" || b.Component.Version != "15.6" || b.NVD == nil || len(b.NVD.CVSS) != 1 || b.KEV == nil || b.EPSS == nil {
		t.Errorf("brief = %+v", b)
	}
	technique := assessment.BriefTechnique{AttackID: "T1190", Name: "Exploit Public-Facing Application", Tactics: []string{"initial-access"}, Role: "exploitation"}
	if !reflect.DeepEqual(b.Techniques, []assessment.BriefTechnique{technique}) ||
		b.Advisories[0].Title != "PostgreSQL security update" || b.Asset.CriticalServices[0].Name != "Pagos en línea" {
		t.Errorf("brief threats = %+v %+v %+v", b.Techniques, b.Advisories, b.Asset.CriticalServices)
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

func TestDossierOfAnAssetWithoutCriticality(t *testing.T) {
	t.Parallel()
	s := stored(t)
	s.Asset = newAsset(t, inventory.CriticalityUnknown)

	d, err := assessment.NewDossier(s)
	if err != nil {
		t.Fatal(err)
	}

	if d.Asset.Criticality != "unknown" || d.Asset.Exposure != "unknown" {
		t.Errorf("asset = %+v, want unknown codes", d.Asset)
	}
}
