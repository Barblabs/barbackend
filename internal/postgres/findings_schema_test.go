package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// findingFixture stores one Asset and one Vulnerability, and returns a
// connection and the Asset's key for inserting Findings by hand.
func findingFixture(t *testing.T) (*pgx.Conn, uuid.UUID, string) {
	t.Helper()
	db, conn := newDBWithConn(t)
	src := newSource(t, db, newCustomer(t, db))
	ctx := context.Background()
	source := uuid.UUID(src.ID())
	if _, err := conn.Exec(ctx, `INSERT INTO assets (cmdb_source_id, record_id, name, description, kind_id, retired)
		VALUES ($1, '32', 'payments server', '', 1, false)`, source); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO vulnerabilities (cve_id, object, modified_at)
		VALUES ('CVE-2021-23017', '{}', now())`); err != nil {
		t.Fatal(err)
	}
	return conn, source, "32"
}

const insertFinding = `INSERT INTO findings (id, cmdb_source_id, record_id, product_vendor, product_name, cve_id,
	component_name, component_version, evidence, first_opened_at, opened_at, closed_at, close_reason_id)
	VALUES ($1, $2, $3, $4, $5, 'CVE-2021-23017', 'nginx of payments', '1.18.0', '{}',
	'2026-03-01', $6::timestamptz, $7::timestamptz, $8)`

func TestFindingsAcceptAnOpenAndAClosedFinding(t *testing.T) {
	t.Parallel()
	conn, source, record := findingFixture(t)
	ctx := context.Background()
	if _, err := conn.Exec(ctx, insertFinding, uuid.New(), source, record, "f5", "nginx", "2026-03-01", nil, nil); err != nil {
		t.Fatalf("open Finding: %v", err)
	}
	if _, err := conn.Exec(ctx, insertFinding, uuid.New(), source, record, "apache", "http_server", "2026-03-01", "2026-03-09", 1); err != nil {
		t.Fatalf("closed Finding: %v", err)
	}
}

func TestFindingsRejectInvalidRows(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		vendor, product  string
		opened           string
		closed, reason   any
		duplicateOfFirst bool
	}{
		{name: "upper case vendor", vendor: "F5", product: "nginx", opened: "2026-03-01"},
		{name: "padded product", vendor: "f5", product: " nginx", opened: "2026-03-01"},
		{name: "empty product", vendor: "f5", product: "", opened: "2026-03-01"},
		{name: "closed without a reason", vendor: "f5", product: "nginx", opened: "2026-03-01", closed: "2026-03-09"},
		{name: "a reason while open", vendor: "f5", product: "nginx", opened: "2026-03-01", reason: 1},
		{name: "unknown reason", vendor: "f5", product: "nginx", opened: "2026-03-01", closed: "2026-03-09", reason: 99},
		{name: "opened before first opened", vendor: "f5", product: "nginx", opened: "2026-02-01"},
		{name: "closed before opened", vendor: "f5", product: "nginx", opened: "2026-03-01", closed: "2026-02-20", reason: 1},
		{name: "same Asset, Product and Vulnerability twice", vendor: "f5", product: "nginx", opened: "2026-03-01", duplicateOfFirst: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			conn, source, record := findingFixture(t)
			ctx := context.Background()
			if tt.duplicateOfFirst {
				if _, err := conn.Exec(ctx, insertFinding, uuid.New(), source, record, "f5", "nginx", "2026-03-01", nil, nil); err != nil {
					t.Fatal(err)
				}
			}
			_, err := conn.Exec(ctx, insertFinding, uuid.New(), source, record, tt.vendor, tt.product, tt.opened, tt.closed, tt.reason)
			if !isConstraintViolation(err) {
				t.Fatalf("insert error = %v, want a constraint violation", err)
			}
		})
	}
}

func TestVulnerabilitiesRejectAnIDThatIsNotACVE(t *testing.T) {
	t.Parallel()
	_, conn := newDBWithConn(t)
	_, err := conn.Exec(context.Background(), `INSERT INTO vulnerabilities (cve_id, object, modified_at) VALUES ('GHSA-xxxx', '{}', now())`)
	if !isConstraintViolation(err) {
		t.Fatalf("insert error = %v, want a constraint violation", err)
	}
}

// isConstraintViolation reports an integrity constraint violation (SQLSTATE
// class 23), not any other failure such as a typo in the test's SQL.
func isConstraintViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && strings.HasPrefix(pgErr.Code, "23")
}
