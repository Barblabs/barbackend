package findings

import (
	"context"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
)

// RescoreAsset rescores every open Finding of the Asset from its stored
// Vulnerability and the Asset's values, with its effective Exposure, after a
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
		for _, f := range open {
			v, err := storedVulnerability(ctx, tx, f.Key.CVE)
			if err != nil {
				return err
			}
			if err := s.score(ctx, tx, f.ID, v, f.Values); err != nil {
				return err
			}
		}
		return nil
	})
}
