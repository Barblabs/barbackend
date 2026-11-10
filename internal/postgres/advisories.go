package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"barbackend/internal/postgres/sqlcgen"
)

// StoredAdvisory is an Advisory that names a stored Vulnerability (ADR 0022):
// its STIX report is opaque here, and its use case decodes it.
type StoredAdvisory struct {
	ID        string
	Feed      string
	Published time.Time
	Object    json.RawMessage
	Modified  time.Time
}

// StoreAdvisory stores a, or replaces it when its Feed published it again,
// and links it to the stored Vulnerabilities of cves. Links already there are
// kept, and none is removed (ADR 0022).
func (t *Tx) StoreAdvisory(ctx context.Context, a StoredAdvisory, cves []string) error {
	if err := t.q.UpsertAdvisory(ctx, sqlcgen.UpsertAdvisoryParams{
		ID: a.ID, Feed: a.Feed, PublishedAt: a.Published, Object: a.Object, ModifiedAt: a.Modified,
	}); err != nil {
		return fmt.Errorf("store advisory %s: %w", a.ID, err)
	}
	if err := t.q.LinkAdvisory(ctx, sqlcgen.LinkAdvisoryParams{AdvisoryID: a.ID, CveIds: cves}); err != nil {
		return fmt.Errorf("link advisory %s to %d cves: %w", a.ID, len(cves), err)
	}
	return nil
}

// AdvisoriesOf is the Advisories linked to the stored Vulnerability of cve,
// newest first.
func (t *Tx) AdvisoriesOf(ctx context.Context, cve string) ([]StoredAdvisory, error) {
	rows, err := t.q.ListAdvisoriesOfVulnerability(ctx, cve)
	if err != nil {
		return nil, fmt.Errorf("list advisories of %s: %w", cve, err)
	}
	out := make([]StoredAdvisory, len(rows))
	for i, row := range rows {
		out[i] = StoredAdvisory{ID: row.ID, Feed: row.Feed, Published: row.PublishedAt, Object: row.Object, Modified: row.ModifiedAt}
	}
	return out, nil
}
