package assessment_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"barbackend/internal/assessment"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

const pgadminCVE = "CVE-2026-116238"

const pgadminDescription = `In server mode pgAdmin 4 locks an internal account after MAX_LOGIN_ATTEMPTS failed logins (3 by default).
The limit could be bypassed, giving an unauthenticated attacker an unlimited number of password guesses against any internal account, including the administrator's.`

// storedVulnerability is a Vulnerability as it is stored: one object with the
// extensions of every Feed that described it.
func storedVulnerability(t *testing.T, extensions map[stix2.Identifier]any) *stix2.Vulnerability {
	t.Helper()
	opts := []stix2.STIXOption{stix2.OptionDescription(pgadminDescription)}
	for id, value := range extensions {
		opts = append(opts, stix2.OptionExtension(string(id), value))
	}
	v, err := stix2.NewVulnerability(pgadminCVE, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func pgadminInput(t *testing.T) assessment.LabelingInput {
	t.Helper()
	return assessment.NewLabelingInput(storedVulnerability(t, nil), []assessment.AdvisoryFacts{
		{Title: "pgAdmin 4 security update", Description: "Fixes a login lockout bypass."},
	})
}

var catalog = []string{"T1078", "T1110", "T1110.001", "T1190"}

func label(attackID, role, evidence string) assessment.TechniqueLabel {
	return assessment.TechniqueLabel{AttackID: attackID, Role: role, Evidence: evidence, Rationale: "Encaja con lo que describe el CVE."}
}

func TestLabelingInputReadsTheFeedsOfTheVulnerability(t *testing.T) {
	t.Parallel()
	v := storedVulnerability(t, map[stix2.Identifier]any{
		stixext.NVDDefinitionID: stixext.NewNVD(stixext.NVD{
			CWEs: []string{"CWE-307"},
			CVSS: []stixext.CVSS{
				{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Type: "Primary"},
				{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Type: "Secondary"},
			},
			Affected:    []stixext.Affected{{Vendor: "pgadmin", Product: "pgadmin_4"}},
			CNAAffected: []stixext.CNAAffected{{Vendor: "pgadmin.org", Product: "pgAdmin 4"}},
		}),
		stixext.KEVDefinitionID: stixext.NewKEV(stixext.KEV{RequiredAction: "Apply the update.", KnownRansomwareCampaignUse: "Unknown"}),
	})

	got := assessment.NewLabelingInput(v, nil)
	if got.CVE != pgadminCVE || got.Description != pgadminDescription {
		t.Errorf("cve, description = %q, %q", got.CVE, got.Description)
	}
	if !slices.Equal(got.CWEs, []string{"CWE-307"}) || len(got.CVSSVectors) != 1 {
		t.Errorf("cwes = %v, vectors = %v, want CWE-307 and the vector once", got.CWEs, got.CVSSVectors)
	}
	if !slices.Equal(got.AffectedProducts, []string{"pgadmin.org pgAdmin 4"}) {
		t.Errorf("products = %v, want the numbering authority's", got.AffectedProducts)
	}
	if got.KEV == nil || got.KEV.RequiredAction != "Apply the update." || got.KEV.KnownRansomwareCampaignUse != "Unknown" {
		t.Errorf("kev = %+v", got.KEV)
	}
}

func TestLabelingInputWithNoFeedDataWritesEmptyListsAndNoKEV(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(assessment.NewLabelingInput(storedVulnerability(t, nil), nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"cwes":[]`, `"cvss_vectors":[]`, `"affected_products":[]`, `"kev":null`, `"advisories":[]`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("input = %s, want %s", raw, want)
		}
	}
}

func TestLabelingInputTakesCPEProductsWhenTheAuthorityNamesNone(t *testing.T) {
	t.Parallel()
	v := storedVulnerability(t, map[stix2.Identifier]any{
		stixext.NVDDefinitionID: stixext.NewNVD(stixext.NVD{Affected: []stixext.Affected{{Vendor: "pgadmin", Product: "pgadmin_4"}}}),
	})

	if got := assessment.NewLabelingInput(v, nil).AffectedProducts; !slices.Equal(got, []string{"pgadmin pgadmin_4"}) {
		t.Errorf("products = %v, want NVD's CPE match", got)
	}
}

func TestVerifyTechniqueLabelsAcceptsLabelsQuotedFromTheInput(t *testing.T) {
	t.Parallel()
	l := assessment.TechniqueLabels{Techniques: []assessment.TechniqueLabel{
		// The quote wraps where the description does not, in another case.
		label("T1110.001", assessment.RoleExploitation, "GIVING an unauthenticated   attacker an unlimited number of password guesses"),
		label("T1078", assessment.RolePrimaryImpact, "against any internal account, including the administrator's"),
		label("T1190", assessment.RoleSecondaryImpact, "Fixes a login lockout bypass."),
	}}

	if got := assessment.VerifyTechniqueLabels(pgadminInput(t), catalog, l); len(got) != 0 {
		t.Errorf("violations = %v, want none", got)
	}
}

func TestVerifyTechniqueLabelsAcceptsNoTechniques(t *testing.T) {
	t.Parallel()
	if got := assessment.VerifyTechniqueLabels(pgadminInput(t), catalog, assessment.TechniqueLabels{}); len(got) != 0 {
		t.Errorf("violations = %v, want none: an empty list is a valid answer", got)
	}
}

func TestVerifyTechniqueLabelsRejects(t *testing.T) {
	t.Parallel()
	quote := "an unlimited number of password guesses"
	tests := []struct {
		name   string
		labels []assessment.TechniqueLabel
		want   string
	}{
		{"a technique not in the catalog", []assessment.TechniqueLabel{label("T1000", assessment.RoleExploitation, quote)}, "is not a technique of the catalog"},
		{"a technique twice", []assessment.TechniqueLabel{label("T1078", assessment.RoleExploitation, quote), label("T1078", assessment.RolePrimaryImpact, quote)}, "is labeled twice"},
		{"an unknown role", []assessment.TechniqueLabel{label("T1078", "impact", quote)}, `role "impact"`},
		{"a quote not in the input", []assessment.TechniqueLabel{label("T1078", assessment.RoleExploitation, "an attacker can execute arbitrary code")}, "is not an exact quote"},
		{"too short a quote", []assessment.TechniqueLabel{label("T1078", assessment.RoleExploitation, "password")}, "shorter than"},
		{"no rationale", []assessment.TechniqueLabel{{AttackID: "T1078", Role: assessment.RoleExploitation, Evidence: quote, Rationale: " "}}, "gives no rationale"},
		{"a URL", []assessment.TechniqueLabel{{AttackID: "T1078", Role: assessment.RoleExploitation, Evidence: quote, Rationale: "Ver https://attack.mitre.org/techniques/T1078/"}}, "writes a URL"},
		{"more than five", []assessment.TechniqueLabel{
			label("T1078", assessment.RoleExploitation, quote), label("T1110", assessment.RoleExploitation, quote),
			label("T1110.001", assessment.RoleExploitation, quote), label("T1190", assessment.RoleExploitation, quote),
			label("T1078", assessment.RolePrimaryImpact, quote), label("T1110", assessment.RolePrimaryImpact, quote),
		}, "more than 5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := assessment.VerifyTechniqueLabels(pgadminInput(t), catalog, assessment.TechniqueLabels{Techniques: tt.labels})
			if !slices.ContainsFunc(got, func(v string) bool { return strings.Contains(v, tt.want) }) {
				t.Errorf("violations = %v, want one with %q", got, tt.want)
			}
		})
	}
}
