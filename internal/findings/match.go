package findings

import (
	"barbackend/internal/finding"
	"barbackend/internal/inventory"
	"barbackend/internal/matching"
	"barbackend/internal/postgres"
	"barbackend/internal/stixext"
)

// candidateMatch is a Match with what scoring needs of its Asset.
type candidateMatch struct {
	finding.Match
	asset finding.AssetValues
}

// bestMatches matches the Vulnerability cve, described by n, against every
// candidate, and keeps one Match per Finding: an Asset with a Product
// installed twice gets the most certain match, and between equally certain
// ones the first in the Asset's order (ADR 0020). Candidates come ordered by
// Asset and position.
func bestMatches(candidates []postgres.Candidate, cve string, n stixext.NVD) []candidateMatch {
	var out []candidateMatch
	at := make(map[finding.Key]int)
	for _, c := range candidates {
		r := matching.Match(c.Component, n)
		if !r.Matched {
			continue
		}
		m, err := finding.NewMatch(c.Asset, c.Component, cve, r)
		if err != nil {
			continue
		}
		next := candidateMatch{Match: m, asset: c.Values}
		i, seen := at[m.Key]
		switch {
		case !seen:
			at[m.Key] = len(out)
			out = append(out, next)
		case len(out[i].Flags) > 0 && len(m.Flags) == 0:
			out[i] = next
		}
	}
	return out
}

// affectedProducts is the Products the Vulnerability's entries name, once
// each in lower case.
func affectedProducts(n stixext.NVD) []inventory.Product {
	seen := make(map[inventory.Product]bool)
	var out []inventory.Product
	for _, a := range n.Affected {
		vendor, name := finding.ProductKey(inventory.Product{Vendor: a.Vendor, Name: a.Product})
		p := inventory.Product{Vendor: vendor, Name: name}
		if vendor == "" || name == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
