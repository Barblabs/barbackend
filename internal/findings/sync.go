package findings

import (
	"context"
	"errors"
	"fmt"

	"barbackend/internal/finding"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/stixext"
)

// productOn is one Product installed on one Asset.
type productOn struct {
	asset           inventory.SourceReference
	vendor, product string
}

// AfterSync matches every Active Asset of the CMDB Source again against the
// stored Vulnerabilities that name its Products, once a Sync of it committed
// (ADR 0019). The Findings of its Inactive Assets are closed as
// asset_inactive. A match opens, updates or reopens its Finding and rescores
// it, so a new Asset is matched against every Vulnerability already stored.
// An open Finding that no longer matches is closed: component_removed when
// its Asset has no component with that Product any more, no_longer_affected
// otherwise. Each Vulnerability is one transaction; one that fails leaves its
// Findings as they were and is returned, joined with the others.
func (s *Service) AfterSync(ctx context.Context, source inventory.CMDBSourceID) error {
	if err := s.db.InTx(ctx, func(tx *postgres.Tx) error {
		_, err := tx.CloseFindingsOfInactiveAssets(ctx, source)
		return err
	}); err != nil {
		return err
	}
	candidates, err := postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]postgres.Candidate, error) {
		return tx.ComponentsOfSource(ctx, source)
	})
	if err != nil {
		return err
	}
	installed, products := installedProducts(candidates)
	vulnerabilities, err := postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]postgres.StoredVulnerability, error) {
		return tx.VulnerabilitiesAffecting(ctx, string(stixext.NVDDefinitionID), products)
	})
	if err != nil {
		return err
	}
	matched := make(map[finding.Key]bool)
	failed := make(map[string]bool)
	var errs []error
	for _, sv := range vulnerabilities {
		saved, err := s.rematch(ctx, sv, candidates)
		if err != nil {
			failed[sv.CVE] = true
			errs = append(errs, fmt.Errorf("%s: %w", sv.CVE, err))
			continue
		}
		for k := range saved {
			matched[k] = true
		}
	}
	if err := s.closeUnmatched(ctx, source, installed, matched, failed); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// rematch saves and scores every match of a stored Vulnerability against the
// candidates, in one transaction.
func (s *Service) rematch(ctx context.Context, sv postgres.StoredVulnerability, candidates []postgres.Candidate) (map[finding.Key]bool, error) {
	v, err := stored(sv)
	if err != nil {
		return nil, err
	}
	n, ok := stixext.NVDOf(v)
	if !ok {
		return nil, nil
	}
	matches := bestMatches(candidates, sv.CVE, n)
	if len(matches) == 0 {
		return nil, nil
	}
	return postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) (map[finding.Key]bool, error) {
		return s.save(ctx, tx, v, matches)
	})
}

// closeUnmatched closes the source's open Findings that no Vulnerability
// matched again, except those of a Vulnerability that failed, which are left
// as they were.
func (s *Service) closeUnmatched(ctx context.Context, source inventory.CMDBSourceID, installed map[productOn]bool, matched map[finding.Key]bool, failed map[string]bool) error {
	return s.db.InTx(ctx, func(tx *postgres.Tx) error {
		open, err := tx.OpenFindingsOfSource(ctx, source)
		if err != nil {
			return err
		}
		for _, f := range open {
			if matched[f.Key] || failed[f.Key.CVE] {
				continue
			}
			reason := finding.NoLongerAffected
			if !installed[productOn{asset: f.Key.Asset, vendor: f.Key.Vendor, product: f.Key.Product}] {
				reason = finding.ComponentRemoved
			}
			if _, err := tx.CloseFinding(ctx, f.ID, reason); err != nil {
				return err
			}
		}
		return nil
	})
}

// installedProducts is which Product is installed on which Asset, and every
// Product once.
func installedProducts(candidates []postgres.Candidate) (map[productOn]bool, []inventory.Product) {
	installed := make(map[productOn]bool)
	seen := make(map[inventory.Product]bool)
	var products []inventory.Product
	for _, c := range candidates {
		vendor, name := finding.ProductKey(c.Component.Product)
		if vendor == "" || name == "" {
			continue
		}
		installed[productOn{asset: c.Asset, vendor: vendor, product: name}] = true
		p := inventory.Product{Vendor: vendor, Name: name}
		if !seen[p] {
			seen[p] = true
			products = append(products, p)
		}
	}
	return installed, products
}
