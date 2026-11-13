package assessment_test

import (
	"testing"

	"barbackend/internal/assessment"
	"barbackend/internal/inventory"
	"barbackend/internal/scoring"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
	"github.com/google/uuid"
)

const (
	cve      = "CVE-2025-1094"
	osCVE    = "CVE-2024-6387"
	advisory = "https://www.postgresql.org/support/security/CVE-2025-1094/"
	finding  = "f-1"
	osFind   = "f-2"
)

func newAsset(t *testing.T, criticality inventory.Criticality) *inventory.Asset {
	t.Helper()
	imported, err := inventory.NewImportedAsset(inventory.ImportedAssetParams{
		Name:        "pg-prod-01",
		Kind:        inventory.Server,
		Criticality: criticality,
		Lifecycle:   inventory.LifecycleProduction,
		Owner:       mustOwner(t, "owner@example.com"),
		Software: []inventory.SoftwareComponent{
			{Role: inventory.OperatingSystem, Name: "Ubuntu Server", Version: "22.04"},
			{Role: inventory.Application, Name: "PostgreSQL", Version: "15.6"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := inventory.NewAsset(inventory.SourceReference{Source: inventory.CMDBSourceID(uuid.New()), RecordID: "1"}, imported)
	if err != nil {
		t.Fatal(err)
	}
	return asset
}

func mustOwner(t *testing.T, email string) inventory.OwnerEmail {
	t.Helper()
	owner, err := inventory.NewOwnerEmail(email)
	if err != nil {
		t.Fatal(err)
	}
	return owner
}

// vulnerability is a stored Vulnerability, with the extensions of the Feeds
// that list it.
func vulnerability(t *testing.T, id, description string, extensions map[stix2.Identifier]any, urls ...string) *stix2.Vulnerability {
	t.Helper()
	refs := []*stix2.ExternalReference{{Name: "cve", ExternalID: id}}
	for _, url := range urls {
		refs = append(refs, &stix2.ExternalReference{Name: "ref", URL: url})
	}
	options := []stix2.STIXOption{stix2.OptionDescription(description), stix2.OptionExternalReferences(refs)}
	for definition, value := range extensions {
		options = append(options, stix2.OptionExtension(string(definition), value))
	}
	v, err := stix2.NewVulnerability(id, options...)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func nvdExtension(metrics ...stixext.CVSS) any {
	return stixext.NewNVD(stixext.NVD{
		VulnStatus:  "Deferred",
		CVSS:        metrics,
		CNAAffected: []stixext.CNAAffected{{Product: "PostgreSQL", Versions: []stixext.CNAVersion{{Version: "15", LessThan: "15.11", Status: "affected"}}}},
	})
}

// stored is the Finding of CVE-2025-1094 on PostgreSQL, listed by every Feed,
// labeled with an exploitation Technique that has one Mitigation, on an
// Asset that runs the Customer's payments.
func stored(t *testing.T) assessment.Stored {
	t.Helper()
	return assessment.Stored{
		Finding: finding,
		Vulnerability: vulnerability(t, cve, "PostgreSQL before 15.11 is affected, as is CVE-2025-1095.", map[stix2.Identifier]any{
			stixext.NVDDefinitionID:  nvdExtension(stixext.CVSS{Version: "3.1", BaseScore: 8.1, Type: "Secondary"}),
			stixext.KEVDefinitionID:  stixext.NewKEV(stixext.KEV{DateAdded: "2025-09-29", RequiredAction: "Apply mitigations.", KnownRansomwareCampaignUse: "Unknown"}),
			stixext.EPSSDefinitionID: stixext.NewEPSS(stixext.EPSS{Probability: 0.9003, Percentile: 0.99794, ScoreDate: "2026-11-02"}),
		}, advisory),
		Asset:         newAsset(t, inventory.CriticalityHigh),
		ComponentName: "PostgreSQL", ComponentVersion: "15.6",
		Score: scoring.Score{
			Model: 2, Value: 0.91312,
			Factors: scoring.Factors{Alpha: 0.81, Beta: 0.9003, Gamma: 1, Vulnerability: 0.9131, CriticalityMultiplier: 1, ExposureMultiplier: 1, LifecycleMultiplier: 1},
			Gaps:    []scoring.DataGap{scoring.ExposureUndeclared},
		},
		Advisories: []assessment.Advisory{{Title: "PostgreSQL security update", Published: "2025-02-13", Feed: "aws", Description: "Amazon RDS for PostgreSQL applied the fix."}},
		Labeling:   assessment.Labeling{Outcome: assessment.LabelingLabeled, Model: "claude-haiku-5-5"},
		Techniques: []assessment.Technique{{
			AttackID: "T1190", Name: "Exploit Public-Facing Application", Tactics: []string{"initial-access"}, Role: assessment.RoleExploitation,
			Evidence: "PostgreSQL before 15.11 is affected", Rationale: "Una inyección en un servicio expuesto.",
			Mitigations: []assessment.Mitigation{{AttackID: "M1051", Name: "Update Software", Advice: "Update the software regularly."}},
		}},
		CriticalServices: []assessment.CriticalService{{Name: "Pagos en línea", Description: "Cobros con tarjeta.", Impact: "critical", MaxDowntime: "1h_4h"}},
	}
}

// dossier is the Dossier of stored.
func dossier(t *testing.T) assessment.Dossier {
	t.Helper()
	d, err := assessment.NewDossier(stored(t))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// osDossier is a Finding on the same Asset's Ubuntu Server that only NVD
// lists and the Cartógrafo has not labeled, so EPSS is a Data Gap.
func osDossier(t *testing.T) assessment.Dossier {
	t.Helper()
	d, err := assessment.NewDossier(assessment.Stored{
		Finding: osFind,
		Vulnerability: vulnerability(t, osCVE, "A race condition in OpenSSH's server.", map[stix2.Identifier]any{
			stixext.NVDDefinitionID: stixext.NewNVD(stixext.NVD{CVSS: []stixext.CVSS{{Version: "3.1", BaseScore: 8.1, Type: "Primary"}}}),
		}),
		Asset:         newAsset(t, inventory.CriticalityHigh),
		ComponentName: "Ubuntu Server", ComponentVersion: "22.04",
		Score: scoring.Score{
			Model: 1, Value: 0.5,
			Factors: scoring.Factors{Alpha: 0.81, Beta: 0.1, Gamma: 0, Vulnerability: 0.5, CriticalityMultiplier: 1, ExposureMultiplier: 1, LifecycleMultiplier: 1},
			Gaps:    []scoring.DataGap{scoring.EPSSPending, scoring.ExposureUndeclared},
		},
		Labeling: assessment.Labeling{Outcome: assessment.LabelingNotTried},
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func briefs(t *testing.T) []assessment.Brief {
	t.Helper()
	return []assessment.Brief{dossier(t).Brief(), osDossier(t).Brief()}
}

func ptr[T any](v T) *T { return &v }
