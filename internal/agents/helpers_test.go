package agents_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"barbackend/internal/agents"
	"barbackend/internal/assessment"
	"barbackend/internal/claude"
	"barbackend/internal/claude/claudetest"
	"barbackend/internal/finding"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/scoring"
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

var (
	ubuntu     = inventory.SoftwareComponent{Role: inventory.OperatingSystem, Name: "Ubuntu Server", Version: "22.04", Product: inventory.Product{Vendor: "canonical", Name: "ubuntu_linux"}}
	postgreSQL = inventory.SoftwareComponent{Role: inventory.Application, Name: "PostgreSQL", Version: "15.6", Product: inventory.Product{Vendor: "postgresql", Name: "postgresql"}}
)

type env struct {
	db       *postgres.DB
	llm      *claudetest.Server
	svc      *agents.Service
	user     tenancy.User
	customer tenancy.CustomerID
	source   inventory.CMDBSourceID
	found    *storedFindings
}

// storedFindings are the ids of the Findings storeFindings stored.
type storedFindings struct {
	pg, os string
}

func newEnv(t *testing.T) env {
	t.Helper()
	db, err := postgres.Open(context.Background(), pgtest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	crew, llm := newCrew(t)
	e := env{db: db, llm: llm, svc: agents.NewService(db, crew), found: &storedFindings{}}
	e.user, e.source = e.newCustomerWithSource(t, "pg-prod-01")
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
	user, _ := e.newCustomerWithSource(t, assetName)
	return user
}

func (e env) newCustomerWithSource(t *testing.T, assetName string) (tenancy.User, inventory.CMDBSourceID) {
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
	return user, source.ID()
}

// pg and os are the ids of the Findings storeFindings stored.
func (e env) pg() string { return e.found.pg }
func (e env) os() string { return e.found.os }

// storeFindings stores, on the Customer's Asset, the Finding of CVE-2025-1094
// on PostgreSQL, in KEV, and of CVE-2024-6387 on Ubuntu Server, scored as
// findings does.
func (e env) storeFindings(t *testing.T) {
	t.Helper()
	if e.found.pg != "" {
		return
	}
	e.found.pg = e.storeFinding(t, pgVulnerability(t), postgreSQL, pgScore())
	e.found.os = e.storeFinding(t, osVulnerability(t), ubuntu, osScore())
}

// storeFinding stores v, the Finding of v on the component of the Customer's
// Asset and its Score, and returns its id.
func (e env) storeFinding(t *testing.T, v *stix2.Vulnerability, c inventory.SoftwareComponent, s scoring.Score) string {
	t.Helper()
	ctx := context.Background()
	object, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	key, err := finding.NewKey(inventory.SourceReference{Source: e.source, RecordID: "1"}, c.Product, v.Name)
	if err != nil {
		t.Fatal(err)
	}
	var id finding.ID
	err = e.db.InTx(ctx, func(tx *postgres.Tx) error {
		if err := tx.StoreVulnerability(ctx, postgres.StoredVulnerability{CVE: v.Name, Object: object, Modified: time.Now()}); err != nil {
			return err
		}
		if id, _, err = tx.SaveMatch(ctx, finding.Match{Key: key, Component: c}); err != nil {
			return err
		}
		_, err := tx.SaveScoreIfChanged(ctx, id, s)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}

// rescore stores s as the newest Score of the Finding of that id.
func (e env) rescore(t *testing.T, id string, s scoring.Score) {
	t.Helper()
	err := e.db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.SaveScoreIfChanged(context.Background(), finding.ID(uuid.MustParse(id)), s)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// prioritize stores the Customer's Findings and a verified Prioritization of
// them, and returns it.
func (e env) prioritize(t *testing.T) agents.Prioritization {
	t.Helper()
	e.storeFindings(t)
	e.llm.Queue(claudetest.JSON(t, validPlacement(e.pg(), e.os())))
	if _, err := e.svc.Prioritize(context.Background(), e.customer); err != nil {
		t.Fatal(err)
	}
	return e.latest(t)
}

func (e env) latest(t *testing.T) agents.Prioritization {
	t.Helper()
	p, err := e.svc.Latest(context.Background(), e.user)
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
		Software:    []inventory.SoftwareComponent{ubuntu, postgreSQL},
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

// pgVulnerability is CVE-2025-1094 as NVD and KEV describe it, without EPSS.
func pgVulnerability(t *testing.T) *stix2.Vulnerability {
	t.Helper()
	return vulnerability(t, cve, "PostgreSQL before 15.11 is affected.",
		stix2.OptionExtension(string(stixext.KEVDefinitionID), stixext.NewKEV(stixext.KEV{DateAdded: "2025-02-13", RequiredAction: "Apply mitigations."})))
}

// osVulnerability is CVE-2024-6387 as NVD describes it.
func osVulnerability(t *testing.T) *stix2.Vulnerability {
	t.Helper()
	return vulnerability(t, otherCVE, "A race condition in OpenSSH's server.")
}

func vulnerability(t *testing.T, id, description string, options ...stix2.STIXOption) *stix2.Vulnerability {
	t.Helper()
	options = append(options,
		stix2.OptionDescription(description),
		stix2.OptionExternalReferences([]*stix2.ExternalReference{{Name: "cve", ExternalID: id}, {Name: "ref", URL: advisory}}),
		stix2.OptionExtension(string(stixext.NVDDefinitionID), stixext.NewNVD(stixext.NVD{
			VulnStatus:  "Deferred",
			CVSS:        []stixext.CVSS{{Version: "3.1", BaseScore: 8.1, Type: "Secondary"}},
			CNAAffected: []stixext.CNAAffected{{Product: "PostgreSQL", Versions: []stixext.CNAVersion{{Version: "15", LessThan: "15.11", Status: "affected"}}}},
		})),
	)
	v, err := stix2.NewVulnerability(id, options...)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// pgScore and osScore have no EPSS and no declared Exposure, so both carry
// those Data Gaps.
func pgScore() scoring.Score { return score(0.9) }
func osScore() scoring.Score { return score(0.6) }

func score(value float64) scoring.Score {
	return scoring.Score{
		Model: 1, Value: value,
		Factors: scoring.Factors{Alpha: 0.81, Beta: 0.1, Gamma: 1, Vulnerability: value, CriticalityMultiplier: 1, ExposureMultiplier: 1},
		Gaps:    []scoring.DataGap{scoring.EPSSPending, scoring.ExposureUndeclared},
	}
}

// findings are the Dossiers of two Findings on pg-prod-01 that no Customer
// has: CVE-2025-1094 on PostgreSQL, in KEV, and CVE-2024-6387 on Ubuntu
// Server.
func findings(t *testing.T) []assessment.Dossier {
	t.Helper()
	return []assessment.Dossier{
		dossierOf(t, pgFind, pgVulnerability(t), postgreSQL, pgScore()),
		dossierOf(t, osFind, osVulnerability(t), ubuntu, osScore()),
	}
}

func dossierOf(t *testing.T, id string, v *stix2.Vulnerability, c inventory.SoftwareComponent, s scoring.Score) assessment.Dossier {
	t.Helper()
	d, err := assessment.NewDossier(assessment.Stored{
		Finding: id, Vulnerability: v, Asset: newAsset(t), ComponentName: c.Name, ComponentVersion: c.Version, Score: s,
		Labeling: assessment.Labeling{Outcome: assessment.LabelingNotTried},
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

const gapsNamed = " Faltan epss_pending y exposure_undeclared."

// validPlacement orders the Findings of pg and os in two new groups, the
// PostgreSQL one first.
func validPlacement(pg, os string) assessment.Placement {
	return assessment.Placement{Groups: []assessment.PlacedGroup{
		newGroup("Explotada activamente", pg, "CVE-2025-1094 está en KEV desde 2025-02-13 sobre PostgreSQL 15.6.", assessment.FindingEvidence{Finding: pg, Path: "/kev/date_added", Value: "2025-02-13"}),
		newGroup("Después", os, "Ubuntu Server 22.04 no está en KEV.", assessment.FindingEvidence{Finding: os, Path: "/kev", Value: "null"}),
	}}
}

// validList is validPlacement of the Findings of findings.
func validList() assessment.Placement { return validPlacement(pgFind, osFind) }

func newGroup(title, id, reason string, evidence assessment.FindingEvidence) assessment.PlacedGroup {
	return assessment.PlacedGroup{Title: title, Findings: []string{id}, Reason: reason + gapsNamed, Evidence: []assessment.FindingEvidence{evidence}}
}

// standing is a standing group of that number that gains no Finding.
func standing(number int) assessment.PlacedGroup {
	return assessment.PlacedGroup{Standing: &number}
}

func placement(groups ...assessment.PlacedGroup) assessment.Placement {
	return assessment.Placement{Groups: groups}
}

func osEvidence(e env) assessment.FindingEvidence {
	return assessment.FindingEvidence{Finding: e.os(), Path: "/kev", Value: "null"}
}

func pgEvidence(e env) assessment.FindingEvidence {
	return assessment.FindingEvidence{Finding: e.pg(), Path: "/kev/date_added", Value: "2025-02-13"}
}

// prioritizeWith runs the rounds the Customer needs, answering each with the
// next of answers, and returns how many Prioritizations they stored.
func (e env) prioritizeWith(t *testing.T, answers ...assessment.Placement) int {
	t.Helper()
	for _, a := range answers {
		e.llm.Queue(claudetest.JSON(t, a))
	}
	stored, err := e.svc.Prioritize(context.Background(), e.customer)
	if err != nil {
		t.Fatal(err)
	}
	return stored
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

// section is what a prompt holds between the tags of that name.
func section(t *testing.T, prompt, tag string) string {
	t.Helper()
	start, end := strings.Index(prompt, "<"+tag+">"), strings.Index(prompt, "</"+tag+">")
	if start < 0 || end < start {
		t.Fatalf("prompt has no %s section: %s", tag, prompt)
	}
	return prompt[start+len(tag)+2 : end]
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
