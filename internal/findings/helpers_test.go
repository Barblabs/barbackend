package findings_test

import (
	"context"
	"testing"
	"time"

	"barbackend/internal/findings"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/scoring"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

// world is one Customer's CMDB Source in a fresh database, and a Service
// that trusts a KEV catalog for an hour.
type world struct {
	db       *postgres.DB
	conn     *pgx.Conn
	source   inventory.CMDBSourceID
	findings *findings.Service
}

func newWorld(t *testing.T) world {
	t.Helper()
	url := pgtest.URL(t)
	db, err := postgres.Open(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	w := world{db: db, conn: pgtest.Conn(t, url), source: inventory.CMDBSourceID(uuid.New())}
	customer := uuid.New()
	w.exec(t, `INSERT INTO customers (id, name) VALUES ($1, $2)`, customer, customer.String())
	w.exec(t, `INSERT INTO cmdb_sources (id, customer_id, provider, settings, credentials) VALUES ($1, $2, 'itop', '{}', '')`, uuid.UUID(w.source), customer)
	w.findings = findings.New(db, scoring.Model1, time.Hour)
	return w
}

func (w world) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := w.conn.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

// declareExposure stores a Customer Admin's Declaration of the record's
// Exposure, or clears it for Unknown, as the assets use case does, without
// rescoring.
func (w world) declareExposure(t *testing.T, record string, e inventory.Exposure) {
	t.Helper()
	if e == inventory.ExposureUnknown {
		w.exec(t, `UPDATE assets SET declared_exposure_id = NULL, exposure_declared_by = NULL, exposure_declared_at = NULL WHERE record_id = $1`, record)
		return
	}
	w.exec(t, `
		WITH admin AS (
			INSERT INTO users (id, cognito_sub, email, customer_id, role_id)
			SELECT gen_random_uuid(), gen_random_uuid()::text, 'admin@example.com', customer_id, 2
			FROM cmdb_sources WHERE id = $3
			ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
			RETURNING id
		)
		UPDATE assets
		SET declared_exposure_id = $1, exposure_declared_by = (SELECT id FROM admin), exposure_declared_at = now()
		WHERE record_id = $2`, int16(e), record, uuid.UUID(w.source))
}

// server is an Asset record of that Criticality running components.
func server(t *testing.T, id string, criticality inventory.Criticality, components ...inventory.SoftwareComponent) inventory.Record {
	t.Helper()
	imported, err := inventory.NewImportedAsset(inventory.ImportedAssetParams{Name: "server " + id, Kind: inventory.Server, Criticality: criticality, Software: components})
	if err != nil {
		t.Fatal(err)
	}
	return inventory.Record{RecordID: id, Imported: imported}
}

func app(name, vendor, product, version string) inventory.SoftwareComponent {
	return inventory.SoftwareComponent{Role: inventory.Application, Name: name, Version: version, Product: inventory.Product{Vendor: vendor, Name: product}}
}

// sync makes the source's Assets exactly records, as a Sync of its CMDB does.
func (w world) sync(t *testing.T, records ...inventory.Record) {
	t.Helper()
	if _, err := w.db.CommitSync(context.Background(), w.source, time.Now(), func(existing inventory.Stored) (inventory.Reconciliation, error) {
		return inventory.Reconcile(w.source, existing, inventory.Snapshot{Records: records})
	}); err != nil {
		t.Fatal(err)
	}
}

// nvdVulnerability is a CVE as the NVD adapter emits it, with a CVSS 3.1
// Primary score of 8.1.
func nvdVulnerability(t *testing.T, cve, status string, affected ...stixext.Affected) *stix2.Vulnerability {
	t.Helper()
	v, err := stix2.NewVulnerability(cve, stix2.OptionExtension(string(stixext.NVDDefinitionID), stixext.NewNVD(stixext.NVD{
		LastModified: time.Now().UTC().Format(time.RFC3339Nano),
		VulnStatus:   status,
		CVSS:         []stixext.CVSS{{Version: "3.1", BaseScore: 8.1, Type: "Primary"}},
		Affected:     affected,
	})))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func kevListing(t *testing.T, cve string) *stix2.Vulnerability {
	t.Helper()
	v, err := stix2.NewVulnerability(cve, stix2.OptionExtension(string(stixext.KEVDefinitionID), stixext.NewKEV(stixext.KEV{DateAdded: "2026-03-01"})))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func epssScore(t *testing.T, cve string, probability float64) *stix2.Vulnerability {
	t.Helper()
	v, err := stix2.NewVulnerability(cve, stix2.OptionExtension(string(stixext.EPSSDefinitionID), stixext.NewEPSS(stixext.EPSS{Probability: probability, Percentile: 0.5})))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// nginxBefore1201 is the entry of CVE-2021-23017: nginx from 0.6.18 up to,
// not including, 1.20.1.
var nginxBefore1201 = stixext.Affected{Vendor: "f5", Product: "nginx", Version: "*", Update: "*", VersionStartIncluding: "0.6.18", VersionEndExcluding: "1.20.1"}

func batch(objects ...*stix2.Vulnerability) []stix2.STIXObject {
	out := make([]stix2.STIXObject, len(objects))
	for i, o := range objects {
		out[i] = o
	}
	return out
}

func (w world) handleNVD(t *testing.T, objects ...*stix2.Vulnerability) {
	t.Helper()
	if err := w.findings.HandleNVD(context.Background(), batch(objects...)); err != nil {
		t.Fatal(err)
	}
}

// storedFinding is a Finding as a test reads it back.
type storedFinding struct {
	id          uuid.UUID
	version     string
	open        bool
	closeReason string
	flags       int
}

// finding reads the Finding of cve on the Asset record, and whether it exists.
func (w world) finding(t *testing.T, record, cve string) (storedFinding, bool) {
	t.Helper()
	var f storedFinding
	var reason *string
	err := w.conn.QueryRow(context.Background(), `
		SELECT f.id, f.component_version, f.closed_at IS NULL, r.name,
		       (SELECT count(*) FROM finding_match_flags m WHERE m.finding_id = f.id)
		FROM findings f LEFT JOIN finding_close_reasons r ON r.id = f.close_reason_id
		WHERE f.record_id = $1 AND f.cve_id = $2`, record, cve).Scan(&f.id, &f.version, &f.open, &reason, &f.flags)
	if err == pgx.ErrNoRows {
		return storedFinding{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	if reason != nil {
		f.closeReason = *reason
	}
	return f, true
}

func (w world) mustFinding(t *testing.T, record, cve string) storedFinding {
	t.Helper()
	f, ok := w.finding(t, record, cve)
	if !ok {
		t.Fatalf("no finding of %s on record %s", cve, record)
	}
	return f
}

// latestScore is the newest Score of the Finding, with its Data Gaps by name.
func (w world) latestScore(t *testing.T, id uuid.UUID) (gamma, beta float64, gaps []string, scores int) {
	t.Helper()
	if err := w.conn.QueryRow(context.Background(), `
		SELECT s.gamma, s.beta,
		       coalesce((SELECT array_agg(d.name ORDER BY d.id) FROM finding_score_data_gaps g JOIN score_data_gaps d ON d.id = g.gap_id
		                 WHERE g.finding_id = s.finding_id AND g.scored_at = s.scored_at), '{}'),
		       (SELECT count(*) FROM finding_scores a WHERE a.finding_id = s.finding_id)
		FROM finding_scores s WHERE s.finding_id = $1 ORDER BY s.scored_at DESC LIMIT 1`, id).Scan(&gamma, &beta, &gaps, &scores); err != nil {
		t.Fatal(err)
	}
	return gamma, beta, gaps, scores
}

func (w world) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := w.conn.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// latestExposureMultiplier is the exposure multiplier of the Finding's newest Score.
func (w world) latestExposureMultiplier(t *testing.T, id uuid.UUID) float64 {
	t.Helper()
	var m float64
	if err := w.conn.QueryRow(context.Background(),
		`SELECT exposure_multiplier FROM finding_scores WHERE finding_id = $1 ORDER BY scored_at DESC LIMIT 1`, id).Scan(&m); err != nil {
		t.Fatal(err)
	}
	return m
}
