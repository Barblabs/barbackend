package postgres

import (
	"context"
	"fmt"
	"time"

	"barbackend/internal/finding"
	"barbackend/internal/postgres/sqlcgen"
	"barbackend/internal/scoring"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

// ActiveAssetNamesOfCustomer is the distinct names of the Customer's Active
// Assets, as their CMDB Sources write them.
func (t *Tx) ActiveAssetNamesOfCustomer(ctx context.Context, customer tenancy.CustomerID) ([]string, error) {
	names, err := t.q.ListActiveAssetNamesOfCustomer(ctx, uuid.UUID(customer))
	if err != nil {
		return nil, fmt.Errorf("list active asset names of customer %s: %w", customer, err)
	}
	return names, nil
}

// FindingAssetFact is an open Finding of a Customer's Active Assets with its
// Asset's name.
type FindingAssetFact struct {
	ID        finding.ID
	AssetName string
	KEV       bool
	// InTheNews is whether a News Item published since the time asked for
	// names its CVE.
	InTheNews bool
	// Score is its latest Score, the zero Score when it has none.
	Score scoring.Score
}

// OpenFindingAssetFactsOfCustomer is every open Finding of the Customer's
// Active Assets, read in one query. kevExtension is the id of the kev/1
// extension definition.
func (t *Tx) OpenFindingAssetFactsOfCustomer(ctx context.Context, customer tenancy.CustomerID, kevExtension string, newsSince time.Time) ([]FindingAssetFact, error) {
	rows, err := t.q.ListOpenFindingAssetFactsOfCustomer(ctx, sqlcgen.ListOpenFindingAssetFactsOfCustomerParams{
		KevExtensionID: kevExtension, NewsSince: newsSince, CustomerID: uuid.UUID(customer),
	})
	if err != nil {
		return nil, fmt.Errorf("list open finding asset facts of customer %s: %w", customer, err)
	}
	facts := make([]FindingAssetFact, len(rows))
	for i, row := range rows {
		facts[i] = FindingAssetFact{
			ID:        finding.ID(row.ID),
			AssetName: row.AssetName,
			KEV:       row.Kev,
			InTheNews: row.InTheNews,
			Score:     latestScore(row.Model, row.Value),
		}
	}
	return facts, nil
}
