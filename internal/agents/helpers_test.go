package agents_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"barbackend/internal/agents"
	"barbackend/internal/assessment"
	"barbackend/internal/claude"
	"barbackend/internal/claude/claudetest"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/stixext"
	"barbackend/internal/tenancy"
	"github.com/TcM1911/stix2"
	"github.com/google/uuid"
)

const (
	cve      = "CVE-2025-1094"
	otherCVE = "CVE-2024-6387"
	advisory = "https://www.postgresql.org/support/security/CVE-2025-1094/"
	pgFind   = "f-1"
	osFind   = "f-2"
)

type env struct {
	db       *postgres.DB
	llm      *claudetest.Server
	svc      *agents.Service
	user     tenancy.User
	customer tenancy.CustomerID
}

func newEnv(t *testing.T) env {
	t.Helper()
	db, err := postgres.Open(context.Background(), pgtest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	crew, llm := newCrew(t)
	e := env{db: db, llm: llm, svc: agents.NewService(db, crew)}
	e.user = e.newCustomer(t, "pg-prod-01")
	if e.customer, err = e.user.ActsFor(); err != nil {
		t.Fatal(err)
	}
	return e
}

func newCrew(t *testing.T) (*agents.Crew, *claudetest.Server) {
	t.Helper()
	llm := claudetest.New(t)
	return agents.NewCrew(claude.New(llm.URL), agents.DefaultModels()), llm
}

// newCustomer stores a Customer with a Viewer and one synced Asset of that
// name, and returns the Viewer.
func (e env) newCustomer(t *testing.T, assetName string) tenancy.User {
	t.Helper()
	ctx := context.Background()
	id := tenancy.CustomerID(uuid.New())
	customer, err := tenancy.NewCustomer(id, id.String())
	if err != nil {
		t.Fatal(err)
	}
	user := newUser(t, tenancy.Viewer, id)
	source, err := inventory.NewCMDBSource(inventory.CMDBSourceID(uuid.New()), id, "fake")
	if err != nil {
		t.Fatal(err)
	}
	err = e.db.InTx(ctx, func(tx *postgres.Tx) error {
		if _, err := tx.CreateCustomer(ctx, customer); err != nil {
			return err
		}
		if _, err := tx.CreateUser(ctx, user, uuid.NewString()); err != nil {
			return err
		}
		return tx.CreateCMDBSource(ctx, source, []byte(`{}`), []byte{})
	})
	if err != nil {
		t.Fatal(err)
	}
	imported, err := inventory.NewImportedAsset(assetParams(assetName))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := inventory.Snapshot{Records: []inventory.Record{{RecordID: "1", Imported: imported}}}
	_, err = e.db.CommitSync(ctx, source.ID(), time.Now(), func(existing inventory.Stored) (inventory.Reconciliation, error) {
		return inventory.Reconcile(source.ID(), existing, snapshot)
	})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

// prioritize stores a verified Prioritization of findings for the Customer.
func (e env) prioritize(t *testing.T) agents.Prioritization {
	t.Helper()
	e.llm.Queue(claudetest.JSON(t, validList()))
	p, err := e.svc.Prioritize(context.Background(), e.customer, findings(t))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func assetParams(name string) inventory.ImportedAssetParams {
	return inventory.ImportedAssetParams{
		Name:        name,
		Kind:        inventory.Server,
		Criticality: inventory.CriticalityHigh,
		Software: []inventory.SoftwareComponent{
			{Role: inventory.OperatingSystem, Name: "Ubuntu Server", Version: "22.04"},
			{Role: inventory.Application, Name: "PostgreSQL", Version: "15.6"},
		},
	}
}

func newUser(t *testing.T, role tenancy.Role, customer tenancy.CustomerID) tenancy.User {
	t.Helper()
	id := uuid.New()
	user, err := tenancy.NewUser(tenancy.UserID(id), id.String()+"@example.com", role, customer)
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func newAsset(t *testing.T) *inventory.Asset {
	t.Helper()
	imported, err := inventory.NewImportedAsset(assetParams("pg-prod-01"))
	if err != nil {
		t.Fatal(err)
	}
	asset, err := inventory.NewAsset(inventory.SourceReference{Source: inventory.CMDBSourceID(uuid.New()), RecordID: "1"}, imported)
	if err != nil {
		t.Fatal(err)
	}
	return asset
}

// findings are two Findings on pg-prod-01: CVE-2025-1094 on PostgreSQL, in
// KEV, and CVE-2024-6387 on Ubuntu Server. Neither has EPSS or a declared
// Exposure, so both carry those Data Gaps.
func findings(t *testing.T) []assessment.Dossier {
	t.Helper()
	kev, err := stix2.NewVulnerability(cve, stix2.OptionExtension(string(stixext.KEVDefinitionID), stixext.NewKEV(stixext.KEV{DateAdded: "2025-02-13", RequiredAction: "Apply mitigations."})))
	if err != nil {
		t.Fatal(err)
	}
	return []assessment.Dossier{
		dossierOf(t, pgFind, cve, "PostgreSQL", assessment.Feeds{KEV: kev, NVD: nvdRecord(t, cve, 8.1)}),
		dossierOf(t, osFind, otherCVE, "Ubuntu Server", assessment.Feeds{NVD: nvdWithDescription(t, otherCVE, 8.1, "A race condition in OpenSSH's server.")}),
	}
}

func dossierOf(t *testing.T, finding, id, component string, feeds assessment.Feeds) assessment.Dossier {
	t.Helper()
	d, err := assessment.NewDossier(finding, id, newAsset(t), component, feeds)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func nvdRecord(t *testing.T, id string, baseScore float64) *stix2.Vulnerability {
	t.Helper()
	return nvdWithDescription(t, id, baseScore, "PostgreSQL before 15.11 is affected.")
}

func nvdWithDescription(t *testing.T, id string, baseScore float64, description string) *stix2.Vulnerability {
	t.Helper()
	v, err := stix2.NewVulnerability(id,
		stix2.OptionDescription(description),
		stix2.OptionExternalReferences([]*stix2.ExternalReference{{Name: "cve", ExternalID: id}, {Name: "ref", URL: advisory}}),
		stix2.OptionExtension(string(stixext.NVDDefinitionID), stixext.NewNVD(stixext.NVD{
			VulnStatus:  "Deferred",
			CVSS:        []stixext.CVSS{{Version: "3.1", BaseScore: baseScore, Type: "Secondary"}},
			CNAAffected: []stixext.CNAAffected{{Product: "PostgreSQL", Versions: []stixext.CNAVersion{{Version: "15", LessThan: "15.11", Status: "affected"}}}},
		})),
	)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func validList() assessment.PriorityList {
	const gaps = " Faltan epss_pending y exposure_undeclared."
	return assessment.PriorityList{Groups: []assessment.PriorityGroup{
		{
			Title:    "Explotada activamente",
			Findings: []string{pgFind},
			Reason:   "CVE-2025-1094 está en KEV desde 2025-02-13 sobre PostgreSQL 15.6." + gaps,
			Evidence: []assessment.FindingEvidence{{Finding: pgFind, Path: "/kev/date_added", Value: "2025-02-13"}},
		},
		{
			Title:    "Después",
			Findings: []string{osFind},
			Reason:   "Ubuntu Server 22.04 no está en KEV." + gaps,
			Evidence: []assessment.FindingEvidence{{Finding: osFind, Path: "/kev", Value: "null"}},
		},
	}}
}

func validPlan() assessment.ActionPlan {
	fixed := "15.11"
	return assessment.ActionPlan{
		Summary:      "PostgreSQL 15.6 está afectado.",
		Steps:        []string{"Actualiza PostgreSQL a 15.11."},
		FixedVersion: &fixed,
		Verification: "Confirma la versión con psql --version.",
		Sources:      []string{advisory},
	}
}

// system and prompt read what a request told the model.
func system(r claudetest.Request) string {
	return r["system"].([]any)[0].(map[string]any)["text"].(string)
}

func prompt(r claudetest.Request) string {
	messages := r["messages"].([]any)
	content := messages[len(messages)-1].(map[string]any)["content"].([]any)
	return content[0].(map[string]any)["text"].(string)
}

// toolResult reads the tool result a request sent back to the model.
func toolResult(t *testing.T, r claudetest.Request) (string, bool) {
	t.Helper()
	messages := r["messages"].([]any)
	content := messages[len(messages)-1].(map[string]any)["content"].([]any)
	block := content[0].(map[string]any)
	if block["type"] != "tool_result" {
		t.Fatalf("last block = %v, want a tool result", block)
	}
	return block["content"].([]any)[0].(map[string]any)["text"].(string), block["is_error"] == true
}

func contains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Errorf("%q does not contain %q", got, want)
	}
}

func wantErr(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Errorf("err = %v, want %v", got, want)
	}
}

func ptr[T any](v T) *T { return &v }
