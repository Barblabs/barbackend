package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"barbackend/internal/finding"
	"barbackend/internal/postgres"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

var errNotACVE = errors.New("not a CVE")

// HandleNVD matches each Vulnerability NVD published or modified against the
// Software Components of every Active Asset with one of its Products
// (ADR 0020). A match stores the Vulnerability and opens, updates or reopens
// its Finding, which is scored. Open Findings of the CVE that no longer match
// are closed, and all of them when NVD rejected it. Each Vulnerability is one
// transaction; a failure is logged and the rest of the batch still runs.
func (s *Service) HandleNVD(ctx context.Context, batch []stix2.STIXObject) error {
	defer s.changed()
	return each(ctx, "nvd", batch, func(v *stix2.Vulnerability) error { return s.matchVulnerability(ctx, v) })
}

func (s *Service) matchVulnerability(ctx context.Context, v *stix2.Vulnerability) error {
	cve, ok := stixext.CVEID(v.Name)
	if !ok {
		return errNotACVE
	}
	n, ok := stixext.NVDOf(v)
	if !ok {
		return nil
	}
	return s.db.InTx(ctx, func(tx *postgres.Tx) error { return s.matchIn(ctx, tx, cve, v, n) })
}

// matchIn matches v, the CVE cve described by n, within tx.
func (s *Service) matchIn(ctx context.Context, tx *postgres.Tx, cve string, v *stix2.Vulnerability, n stixext.NVD) error {
	open, err := tx.OpenFindingsOfVulnerability(ctx, cve)
	if err != nil {
		return err
	}
	if n.VulnStatus == rejected {
		return closeAll(ctx, tx, open, finding.VulnerabilityRejected)
	}
	candidates, err := tx.ComponentsWithProducts(ctx, affectedProducts(n))
	if err != nil {
		return err
	}
	matches := bestMatches(candidates, cve, n)
	if len(matches) == 0 && len(open) == 0 {
		return nil
	}
	merged, err := storeAndRead(ctx, tx, cve, v, n)
	if err != nil {
		return err
	}
	matched, err := s.save(ctx, tx, merged, matches)
	if err != nil {
		return err
	}
	return closeAll(ctx, tx, unmatched(open, matched), finding.NoLongerAffected)
}

// unmatched is the open Findings whose Key is not among matched.
func unmatched(open []postgres.OpenFinding, matched map[finding.Key]bool) []postgres.OpenFinding {
	var out []postgres.OpenFinding
	for _, f := range open {
		if !matched[f.Key] {
			out = append(out, f)
		}
	}
	return out
}

// storeAndRead stores v and reads it back with the extensions other Feeds
// already set on it, which its Score needs.
func storeAndRead(ctx context.Context, tx *postgres.Tx, cve string, v *stix2.Vulnerability, n stixext.NVD) (*stix2.Vulnerability, error) {
	object, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", cve, err)
	}
	if err := tx.StoreVulnerability(ctx, postgres.StoredVulnerability{CVE: cve, Object: object, Modified: modified(n, v)}); err != nil {
		return nil, err
	}
	withFeeds, err := tx.Vulnerability(ctx, cve)
	if err != nil {
		return nil, err
	}
	return stored(withFeeds)
}

// save saves and scores every match of v, and returns the Keys it saved.
func (s *Service) save(ctx context.Context, tx *postgres.Tx, v *stix2.Vulnerability, matches []candidateMatch) (map[finding.Key]bool, error) {
	saved := make(map[finding.Key]bool, len(matches))
	for _, m := range matches {
		id, _, err := tx.SaveMatch(ctx, m.Match)
		if err != nil {
			return nil, err
		}
		if err := s.score(ctx, tx, id, v, m.criticality, m.exposure); err != nil {
			return nil, err
		}
		saved[m.Key] = true
	}
	return saved, nil
}

func closeAll(ctx context.Context, tx *postgres.Tx, open []postgres.OpenFinding, reason finding.CloseReason) error {
	for _, f := range open {
		if _, err := tx.CloseFinding(ctx, f.ID, reason); err != nil {
			return err
		}
	}
	return nil
}

// modified is when NVD last modified the CVE, which orders two versions of
// it; without a readable date it is the object's own modification time.
func modified(n stixext.NVD, v *stix2.Vulnerability) time.Time {
	if t, err := time.Parse(time.RFC3339, n.LastModified); err == nil {
		return t
	}
	if v.Modified != nil {
		return v.Modified.Time
	}
	return time.Now()
}
