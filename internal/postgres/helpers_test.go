package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"barbackend/internal/finding"
	"barbackend/internal/inventory"
	"barbackend/internal/matching"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/stixext"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func inTx(t *testing.T, db *postgres.DB, fn func(*postgres.Tx) error) {
	t.Helper()
	if err := db.InTx(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

func newSource(t *testing.T, db *postgres.DB, customer tenancy.CustomerID) inventory.CMDBSource {
	t.Helper()
	src, err := inventory.NewCMDBSource(inventory.CMDBSourceID(uuid.New()), customer, "itop")
	if err != nil {
		t.Fatal(err)
	}
	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.CreateCMDBSource(context.Background(), src, []byte(`{}`), []byte{})
	})
	return src
}

func newCustomer(t *testing.T, db *postgres.DB) tenancy.CustomerID {
	t.Helper()
	id := tenancy.CustomerID(uuid.New())
	if err := db.CreateCustomer(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	return id
}

func mustImported(t *testing.T, p inventory.ImportedAssetParams) inventory.ImportedAsset {
	t.Helper()
	a, err := inventory.NewImportedAsset(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

var errReadOnly = errors.New("read only")

func assets(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID) []*inventory.Asset {
	t.Helper()
	return stored(t, db, src).Assets
}

func stored(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID) inventory.Stored {
	t.Helper()
	var got inventory.Stored
	_, err := db.CommitSync(context.Background(), src, time.Now(), func(existing inventory.Stored) (inventory.Reconciliation, error) {
		got = existing
		return inventory.Reconciliation{}, errReadOnly
	})
	if !errors.Is(err, errReadOnly) {
		t.Fatal(err)
	}
	return got
}

func reconcileWith(src inventory.CMDBSourceID, s inventory.Snapshot) func(inventory.Stored) (inventory.Reconciliation, error) {
	return func(existing inventory.Stored) (inventory.Reconciliation, error) {
		return inventory.Reconcile(src, existing, s)
	}
}

func commitSync(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID, reconcile func(inventory.Stored) (inventory.Reconciliation, error)) inventory.SyncRun {
	t.Helper()
	run, err := db.CommitSync(context.Background(), src, time.Now(), reconcile)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func syncRecords(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID, records ...inventory.Record) inventory.Reconciliation {
	t.Helper()
	return syncSnapshot(t, db, src, inventory.Snapshot{Records: records})
}

func syncSnapshot(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID, s inventory.Snapshot) inventory.Reconciliation {
	t.Helper()
	var r inventory.Reconciliation
	reconcile := reconcileWith(src, s)
	commitSync(t, db, src, func(existing inventory.Stored) (inventory.Reconciliation, error) {
		var err error
		r, err = reconcile(existing)
		return r, err
	})
	return r
}

func newDBWithConn(t *testing.T) (*postgres.DB, *pgx.Conn) {
	t.Helper()
	url := pgtest.URL(t)
	db, err := postgres.Open(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db, pgtest.Conn(t, url)
}

func queryInt(t *testing.T, conn *pgx.Conn, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := conn.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func mustOwner(t *testing.T, email string) inventory.OwnerEmail {
	t.Helper()
	o, err := inventory.NewOwnerEmail(email)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// onlyAsset is the one Asset of the Customer, as the Asset list reads it.
func onlyAsset(t *testing.T, db *postgres.DB, customer tenancy.CustomerID) postgres.StoredAsset {
	t.Helper()
	var page postgres.AssetPage
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		page, err = tx.ListAssets(context.Background(), postgres.AssetListQuery{Customer: customer, Limit: 10})
		return err
	})
	if len(page.Assets) != 1 {
		t.Fatalf("assets = %d, want 1", len(page.Assets))
	}
	return page.Assets[0]
}

func declareInternal(t *testing.T, db *postgres.DB, customer tenancy.CustomerID, id int64, by tenancy.UserID) {
	t.Helper()
	inTx(t, db, func(tx *postgres.Tx) error {
		stored, err := tx.CustomerAsset(context.Background(), customer, id)
		if err != nil {
			return err
		}
		if err := stored.Asset.DeclareExposure(inventory.Internal); err != nil {
			return err
		}
		return tx.DeclareExposure(context.Background(), stored.Asset, by)
	})
}

func declareConfidential(t *testing.T, db *postgres.DB, customer tenancy.CustomerID, id int64, by tenancy.UserID) {
	t.Helper()
	inTx(t, db, func(tx *postgres.Tx) error {
		stored, err := tx.CustomerAsset(context.Background(), customer, id)
		if err != nil {
			return err
		}
		if err := stored.Asset.DeclareInformationClassification(inventory.ClassifiedConfidential); err != nil {
			return err
		}
		return tx.DeclareInformationClassification(context.Background(), stored.Asset, by)
	})
}

func storeAdvisory(t *testing.T, db *postgres.DB, a postgres.StoredAdvisory, cves ...string) {
	t.Helper()
	inTx(t, db, func(tx *postgres.Tx) error { return tx.StoreAdvisory(context.Background(), a, cves) })
}

func inTxValue[T any](t *testing.T, db *postgres.DB, fn func(*postgres.Tx) (T, error)) T {
	t.Helper()
	v, err := postgres.InTxValue(context.Background(), db, fn)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func fullParams(t *testing.T) inventory.ImportedAssetParams {
	return inventory.ImportedAssetParams{
		Name:        "srv-01",
		Description: "Billing API",
		Kind:        inventory.Server,
		Hardware:    inventory.Hardware{Vendor: "Dell", Model: ""},
		Software: []inventory.SoftwareComponent{
			{Role: inventory.Application, Name: "nginx", Version: "1.24", Product: inventory.Product{Vendor: "f5", Name: "nginx"}},
			{Role: inventory.OperatingSystem, Name: "Ubuntu", Version: "22.04 LTS"},
			{Role: inventory.Application, Name: "custom agent"},
		},
		Criticality: inventory.CriticalityHigh,
		Exposure:    inventory.InternetFacing,
		Lifecycle:   inventory.LifecycleStock,
		Owner:       mustOwner(t, "owner@example.com"),
		Retired:     true,
	}
}

func record(t *testing.T, id string, p inventory.ImportedAssetParams) inventory.Record {
	return inventory.Record{RecordID: id, Imported: mustImported(t, p)}
}

func technique(id, attackID, name string, modified time.Time) postgres.AttackTechnique {
	return postgres.AttackTechnique{
		ID: id, AttackID: attackID, Name: name, Tactics: []string{"initial-access"},
		Object: json.RawMessage(`{"type":"attack-pattern"}`), Modified: modified,
	}
}

func revoked(id, attackID, name string) postgres.AttackTechnique {
	r := technique(id, attackID, name, may)
	r.Revoked = true
	return r
}

func mitigation(id, attackID, name string) postgres.AttackMitigation {
	return postgres.AttackMitigation{ID: id, AttackID: attackID, Name: name, Object: json.RawMessage(`{"type":"course-of-action"}`), Modified: may}
}

func relationship(id, typ, source, target, description string) postgres.AttackRelationship {
	return postgres.AttackRelationship{ID: id, Type: typ, Source: source, Target: target, Description: description, Modified: may}
}

func newFindingWorld(t *testing.T) findingWorld {
	t.Helper()
	db := pgtest.NewDB(t)
	customer := newCustomer(t, db)
	src := newSource(t, db, customer)
	w := findingWorld{
		db:       db,
		customer: customer,
		source:   src.ID(),
		payments: inventory.SourceReference{Source: src.ID(), RecordID: "1"},
		lab:      inventory.SourceReference{Source: src.ID(), RecordID: "2"},
	}
	syncRecords(t, db, src.ID(), w.paymentsRecord(t), w.labRecord(t))
	storeVulnerability(t, db, "CVE-2021-23017", time.Now(), vulnerabilityObject("CVE-2021-23017", "Analyzed", `[]`))
	return w
}

// match builds the Match of CVE-2021-23017 on nginx of asset at version.
func match(t *testing.T, asset inventory.SourceReference, version string, flags ...matching.Flag) finding.Match {
	t.Helper()
	c := nginx
	c.Version = version
	m, err := finding.NewMatch(asset, c, "CVE-2021-23017", matching.Result{
		Matched: true, Evidence: stixext.Affected{Vendor: "f5", Product: "nginx", Version: "*", VersionEndExcluding: "1.20.1"}, Flags: flags,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func saveMatch(t *testing.T, db *postgres.DB, m finding.Match) (finding.ID, finding.Outcome) {
	t.Helper()
	var id finding.ID
	var outcome finding.Outcome
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		id, outcome, err = tx.SaveMatch(context.Background(), m)
		return err
	})
	return id, outcome
}

func openFindingsOf(t *testing.T, db *postgres.DB, cve string) []postgres.OpenFinding {
	t.Helper()
	var open []postgres.OpenFinding
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		open, err = tx.OpenFindingsOfVulnerability(context.Background(), cve)
		return err
	})
	return open
}

func claim(t *testing.T, db *postgres.DB, now time.Time) (postgres.Invitation, bool) {
	t.Helper()
	var (
		claimed postgres.Invitation
		due     bool
	)
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		claimed, due, err = tx.ClaimInvitation(context.Background(), now, now.Add(time.Minute))
		return err
	})
	return claimed, due
}

func storedCVEs(t *testing.T, cves ...string) *postgres.DB {
	t.Helper()
	db := pgtest.NewDB(t)
	for _, cve := range cves {
		storeVulnerability(t, db, cve, may, vulnerabilityObject(cve, "Analyzed", `[]`))
	}
	return db
}

func storeLabeling(db *postgres.DB, cve string, labels ...postgres.TechniqueLabel) error {
	return db.InTx(context.Background(), func(tx *postgres.Tx) error {
		return tx.StoreLabeling(context.Background(), cve, cartografo, promptHash, labels)
	})
}

func storeFailedLabeling(db *postgres.DB, cve string) error {
	return db.InTx(context.Background(), func(tx *postgres.Tx) error {
		return tx.StoreFailedLabeling(context.Background(), cve, cartografo, promptHash)
	})
}

func storeUser(t *testing.T, db *postgres.DB, email string, role tenancy.Role, customer tenancy.CustomerID) tenancy.User {
	t.Helper()
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), email, role, customer)
	if err != nil {
		t.Fatal(err)
	}
	inTx(t, db, func(tx *postgres.Tx) error {
		return pgtest.CreateUser(context.Background(), tx, u, uuid.NewString())
	})
	return u
}

// vulnerabilityObject is a STIX vulnerability whose nvd/1 extension lists
// affected as given, raw JSON, and has that status.
func vulnerabilityObject(cve, status, affected string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"type":"vulnerability","name":%q,"extensions":{%q:{"vuln_status":%q,"affected":%s}}}`,
		cve, nvdKey, status, affected))
}

func storeVulnerability(t *testing.T, db *postgres.DB, cve string, modified time.Time, object json.RawMessage) {
	t.Helper()
	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.StoreVulnerability(context.Background(), postgres.StoredVulnerability{CVE: cve, Object: object, Modified: modified})
	})
}

func areaRecord(t *testing.T, id, name string, inactive bool) inventory.AreaRecord {
	t.Helper()
	imported, err := inventory.NewImportedArea(inventory.ImportedAreaParams{Name: name, Inactive: inactive})
	if err != nil {
		t.Fatal(err)
	}
	return inventory.AreaRecord{RecordID: id, Imported: imported}
}

func storeCustomer(db *postgres.DB, name string) (postgres.StoredCustomer, error) {
	c, err := tenancy.NewCustomer(tenancy.CustomerID(uuid.New()), name)
	if err != nil {
		return postgres.StoredCustomer{}, err
	}
	var stored postgres.StoredCustomer
	err = db.InTx(context.Background(), func(tx *postgres.Tx) (err error) {
		stored, err = tx.CreateCustomer(context.Background(), c)
		return err
	})
	return stored, err
}

func isConstraintViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && strings.HasPrefix(pgErr.Code, "23")
}
