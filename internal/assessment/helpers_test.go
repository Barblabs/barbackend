package assessment_test

import (
	"testing"

	"barbackend/internal/assessment"
	"barbackend/internal/inventory"
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

func vulnerability(t *testing.T, id, description string, extension stix2.Identifier, value any, urls ...string) *stix2.Vulnerability {
	t.Helper()
	refs := []*stix2.ExternalReference{{Name: "cve", ExternalID: id}}
	for _, url := range urls {
		refs = append(refs, &stix2.ExternalReference{Name: "ref", URL: url})
	}
	v, err := stix2.NewVulnerability(id,
		stix2.OptionDescription(description),
		stix2.OptionExternalReferences(refs),
		stix2.OptionExtension(string(extension), value),
	)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func nvdRecord(t *testing.T, metrics ...stixext.CVSS) *stix2.Vulnerability {
	t.Helper()
	return vulnerability(t, cve, "PostgreSQL before 15.11 is affected, as is CVE-2025-1095.", stixext.NVDDefinitionID, stixext.NewNVD(stixext.NVD{
		VulnStatus:  "Deferred",
		CVSS:        metrics,
		CNAAffected: []stixext.CNAAffected{{Product: "PostgreSQL", Versions: []stixext.CNAVersion{{Version: "15", LessThan: "15.11", Status: "affected"}}}},
	}), advisory)
}

// dossier is the Finding of CVE-2025-1094 on PostgreSQL, listed by every Feed.
func dossier(t *testing.T) assessment.Dossier {
	t.Helper()
	d, err := assessment.NewDossier(finding, cve, newAsset(t, inventory.CriticalityHigh), "PostgreSQL", assessment.Feeds{
		KEV: vulnerability(t, cve, "kev text", stixext.KEVDefinitionID, stixext.NewKEV(stixext.KEV{DateAdded: "2025-09-29", RequiredAction: "Apply mitigations."})),
		EPSS: vulnerability(t, cve, "", stixext.EPSSDefinitionID, stixext.NewEPSS(stixext.EPSS{
			Probability: 0.9003, Percentile: 0.99794, ScoreDate: "2026-11-02",
		})),
		NVD: nvdRecord(t, stixext.CVSS{Version: "3.1", BaseScore: 8.1, Type: "Secondary"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// osDossier is a Finding on the same Asset's Ubuntu Server that only NVD
// lists, so EPSS is a Data Gap.
func osDossier(t *testing.T) assessment.Dossier {
	t.Helper()
	d, err := assessment.NewDossier(osFind, osCVE, newAsset(t, inventory.CriticalityHigh), "Ubuntu Server", assessment.Feeds{
		NVD: vulnerability(t, osCVE, "A race condition in OpenSSH's server.", stixext.NVDDefinitionID, stixext.NewNVD(stixext.NVD{
			CVSS: []stixext.CVSS{{Version: "3.1", BaseScore: 8.1, Type: "Primary"}},
		})),
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
