// Package advisories keeps the Advisories that name a stored Vulnerability
// and links them to it by CVE (ADR 0022). Its Handle functions have the shape
// of ingest.Feed.Handle.
package advisories

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"time"

	"barbackend/internal/postgres"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

// Service links Advisories to stored Vulnerabilities.
type Service struct {
	db *postgres.DB
}

func New(db *postgres.DB) *Service {
	return &Service{db: db}
}

// HandleAWS keeps each AWS Security Bulletin that names a stored
// Vulnerability and links it to the stored ones it names. A bulletin that
// names none is discarded (ADR 0022). The batch is one transaction.
func (s *Service) HandleAWS(ctx context.Context, batch []stix2.STIXObject) error {
	return s.handle(ctx, "aws", batch)
}

func (s *Service) handle(ctx context.Context, feed string, batch []stix2.STIXObject) error {
	reports := make([]*stix2.Report, 0, len(batch))
	var named []string
	for _, obj := range batch {
		if r, ok := obj.(*stix2.Report); ok {
			reports = append(reports, r)
			named = append(named, cvesOf(r)...)
		}
	}
	if len(reports) == 0 {
		return nil
	}
	return s.db.InTx(ctx, func(tx *postgres.Tx) error {
		stored, err := tx.StoredCVEs(ctx, named)
		if err != nil {
			return err
		}
		kept := 0
		for _, r := range reports {
			ok, err := keep(ctx, tx, feed, r, stored)
			if err != nil {
				return err
			}
			if ok {
				kept++
			}
		}
		log.Printf("advisories: %s: kept %d of %d", feed, kept, len(reports))
		return nil
	})
}

// keep stores r and links it to the CVEs it names that are in stored, and
// reports whether it named any.
func keep(ctx context.Context, tx *postgres.Tx, feed string, r *stix2.Report, stored []string) (bool, error) {
	cves := storedOf(cvesOf(r), stored)
	if len(cves) == 0 {
		return false, nil
	}
	a, err := advisory(feed, r)
	if err != nil {
		return false, err
	}
	return true, tx.StoreAdvisory(ctx, a, cves)
}

// cvesOf is the CVEs r names: those its text mentions whose Vulnerability
// it refers to. A Vulnerability's STIX id comes from its CVE and cannot be
// read back (ADR 0010), so the text gives the candidates and object_refs
// confirms them.
func cvesOf(r *stix2.Report) []string {
	var out []string
	for _, cve := range stixext.CVEIDs(r.Name + " " + r.Description) {
		if slices.Contains(r.Objects, stixext.VulnerabilityID(cve)) {
			out = append(out, cve)
		}
	}
	return out
}

// storedOf is the cves that are in stored.
func storedOf(cves, stored []string) []string {
	var out []string
	for _, cve := range cves {
		if slices.Contains(stored, cve) {
			out = append(out, cve)
		}
	}
	return out
}

func advisory(feed string, r *stix2.Report) (postgres.StoredAdvisory, error) {
	object, err := json.Marshal(r)
	if err != nil {
		return postgres.StoredAdvisory{}, fmt.Errorf("encode advisory %s: %w", r.ID, err)
	}
	return postgres.StoredAdvisory{
		ID:        string(r.ID),
		Feed:      feed,
		Published: timeOf(r.Published),
		Object:    object,
		Modified:  timeOf(r.Modified),
	}, nil
}

// timeOf is t, or now when the Feed gave none.
func timeOf(t *stix2.Timestamp) time.Time {
	if t == nil {
		return time.Now().UTC()
	}
	return t.Time
}
