package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"barbackend/internal/finding"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres/sqlcgen"
	"github.com/jackc/pgx/v5"
)

// StoredVulnerability is a Vulnerability that opened a Finding (ADR 0020):
// its STIX object is opaque here, and its use case decodes it.
type StoredVulnerability struct {
	CVE      string
	Object   json.RawMessage
	Modified time.Time
}

// StoreVulnerability stores v, or replaces its NVD data, keeping the
// extensions other Feeds already set (ADR 0010). An older modification never
// replaces a newer one.
func (t *Tx) StoreVulnerability(ctx context.Context, v StoredVulnerability) error {
	if err := t.q.UpsertVulnerability(ctx, sqlcgen.UpsertVulnerabilityParams{
		CveID: v.CVE, Object: v.Object, ModifiedAt: v.Modified,
	}); err != nil {
		return fmt.Errorf("store vulnerability %s: %w", v.CVE, err)
	}
	return nil
}

// SetVulnerabilityExtension sets the extension of that definition id, such as
// kev/1 or epss/1, on a stored Vulnerability. It reports false, changing
// nothing, when the CVE is not stored: no Finding cares about it.
func (t *Tx) SetVulnerabilityExtension(ctx context.Context, cve, definitionID string, extension json.RawMessage) (bool, error) {
	n, err := t.q.SetVulnerabilityExtension(ctx, sqlcgen.SetVulnerabilityExtensionParams{
		CveID: cve, ExtensionID: definitionID, Extension: extension,
	})
	if err != nil {
		return false, fmt.Errorf("set extension %s of vulnerability %s: %w", definitionID, cve, err)
	}
	return n > 0, nil
}

// StoredCVEs is which of cves are stored, in order. A Feed with an entry for
// every CVE asks it once per batch, so it touches only the CVEs a Finding
// cares about.
func (t *Tx) StoredCVEs(ctx context.Context, cves []string) ([]string, error) {
	if len(cves) == 0 {
		return nil, nil
	}
	stored, err := t.q.ListStoredVulnerabilityIDs(ctx, cves)
	if err != nil {
		return nil, fmt.Errorf("list which of %d cves are stored: %w", len(cves), err)
	}
	return stored, nil
}

// Vulnerability fails with ErrNotFound when the CVE is not stored.
func (t *Tx) Vulnerability(ctx context.Context, cve string) (StoredVulnerability, error) {
	row, err := t.q.GetVulnerability(ctx, cve)
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredVulnerability{}, fmt.Errorf("vulnerability %s: %w", cve, ErrNotFound)
	}
	if err != nil {
		return StoredVulnerability{}, fmt.Errorf("get vulnerability %s: %w", cve, err)
	}
	return StoredVulnerability{CVE: row.CveID, Object: row.Object, Modified: row.ModifiedAt}, nil
}

// VulnerabilitiesAffecting is the stored Vulnerabilities whose nvd/1 affected
// entries, under the extension of that definition id, name one of products,
// ignoring case. It is what a Sync matches its Assets against (ADR 0020).
func (t *Tx) VulnerabilitiesAffecting(ctx context.Context, nvdDefinitionID string, products []inventory.Product) ([]StoredVulnerability, error) {
	if len(products) == 0 {
		return nil, nil
	}
	vendors, names := productKeys(products)
	rows, err := t.q.ListVulnerabilitiesAffecting(ctx, sqlcgen.ListVulnerabilitiesAffectingParams{
		NvdExtensionID: nvdDefinitionID, Vendors: vendors, Products: names,
	})
	if err != nil {
		return nil, fmt.Errorf("list vulnerabilities affecting %d products: %w", len(products), err)
	}
	out := make([]StoredVulnerability, len(rows))
	for i, row := range rows {
		out[i] = StoredVulnerability{CVE: row.CveID, Object: row.Object, Modified: row.ModifiedAt}
	}
	return out, nil
}

// productKeys splits products into parallel arrays of their Finding keys.
func productKeys(products []inventory.Product) (vendors, names []string) {
	vendors, names = make([]string, len(products)), make([]string, len(products))
	for i, p := range products {
		vendors[i], names[i] = finding.ProductKey(p)
	}
	return vendors, names
}
