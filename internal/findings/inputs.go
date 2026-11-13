package findings

import (
	"context"
	"encoding/json"
	"fmt"

	"barbackend/internal/postgres"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

// HandleKEV sets the KEV listing of every stored Vulnerability the catalog
// lists and rescores its open Findings. A CVE no Finding cares about is
// ignored, not kept (ADR 0020). The catalog counts as received before the
// rescoring, so the Scores it makes are not stale.
func (s *Service) HandleKEV(ctx context.Context, batch []stix2.STIXObject) error {
	defer s.changed()
	s.kevReceived()
	return s.setScoreInput(ctx, "kev", batch, stixext.KEVDefinitionID)
}

// HandleEPSS sets the EPSS of every stored Vulnerability in the batch and
// rescores its open Findings. EPSS has an entry for every CVE, so it asks
// once per batch which of them are stored and touches only those.
func (s *Service) HandleEPSS(ctx context.Context, batch []stix2.STIXObject) error {
	defer s.changed()
	return s.setScoreInput(ctx, "epss", batch, stixext.EPSSDefinitionID)
}

// setScoreInput sets the extension of that definition on the stored
// Vulnerabilities of batch and rescores their open Findings, one
// transaction per Vulnerability.
func (s *Service) setScoreInput(ctx context.Context, feed string, batch []stix2.STIXObject, definition stix2.Identifier) error {
	extensions := make(map[string]any)
	var cves []string
	for _, obj := range batch {
		v, ok := obj.(*stix2.Vulnerability)
		if !ok {
			continue
		}
		cve, isCVE := stixext.CVEID(v.Name)
		ext, has := v.Extensions[string(definition)]
		if !isCVE || !has {
			continue
		}
		if _, seen := extensions[cve]; !seen {
			cves = append(cves, cve)
		}
		extensions[cve] = ext
	}
	storedCVEs, err := postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]string, error) { return tx.StoredCVEs(ctx, cves) })
	if err != nil {
		return err
	}
	of := make([]stix2.STIXObject, len(storedCVEs))
	for i, cve := range storedCVEs {
		of[i] = &stix2.Vulnerability{Name: cve}
	}
	return each(ctx, feed, of, func(v *stix2.Vulnerability) error {
		return s.rescoreWith(ctx, v.Name, definition, extensions[v.Name])
	})
}

// rescoreWith sets one extension of the stored Vulnerability cve and rescores
// its open Findings, in one transaction.
func (s *Service) rescoreWith(ctx context.Context, cve string, definition stix2.Identifier, extension any) error {
	raw, err := json.Marshal(extension)
	if err != nil {
		return fmt.Errorf("encode %s of %s: %w", definition, cve, err)
	}
	return s.db.InTx(ctx, func(tx *postgres.Tx) error {
		set, err := tx.SetVulnerabilityExtension(ctx, cve, string(definition), raw)
		if err != nil || !set {
			return err
		}
		v, err := storedVulnerability(ctx, tx, cve)
		if err != nil {
			return err
		}
		open, err := tx.OpenFindingsOfVulnerability(ctx, cve)
		if err != nil {
			return err
		}
		for _, f := range open {
			if err := s.score(ctx, tx, f.ID, v, f.Criticality, f.Exposure); err != nil {
				return err
			}
		}
		return nil
	})
}
