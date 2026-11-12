package findings

import (
	"context"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"github.com/TcM1911/stix2"
)

// RescoreAsset rescores every open Finding of the Asset from its stored
// Vulnerability and the Asset's effective Criticality and Exposure, after a
// Declaration changed them (ADR 0021). It reads them afresh in one
// transaction, so of two Declarations close together the last one's Scores
// stand, and stores a Score only when it changed.
func (s *Service) RescoreAsset(ctx context.Context, asset inventory.SourceReference) error {
	defer s.changed()
	return s.db.InTx(ctx, func(tx *postgres.Tx) error {
		open, err := tx.OpenFindingsOfAsset(ctx, asset)
		if err != nil {
			return err
		}
		vulnerabilities := make(map[string]*stix2.Vulnerability)
		for _, f := range open {
			v, err := storedOnce(ctx, tx, vulnerabilities, f.Key.CVE)
			if err != nil {
				return err
			}
			if err := s.score(ctx, tx, f.ID, v, f.Criticality, f.Exposure); err != nil {
				return err
			}
		}
		return nil
	})
}

// storedOnce is the stored Vulnerability cve, read only on its first request,
// since an Asset can have several Findings of one CVE.
func storedOnce(ctx context.Context, tx *postgres.Tx, read map[string]*stix2.Vulnerability, cve string) (*stix2.Vulnerability, error) {
	if v, ok := read[cve]; ok {
		return v, nil
	}
	withFeeds, err := tx.Vulnerability(ctx, cve)
	if err != nil {
		return nil, err
	}
	v, err := stored(withFeeds)
	if err != nil {
		return nil, err
	}
	read[cve] = v
	return v, nil
}
