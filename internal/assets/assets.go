// Package assets holds the use cases on a Customer's Assets: listing them
// across all its CMDB Sources and declaring their Exposure and Information
// Classification (ADR 0008).
package assets

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// ErrInvalidQuery is a list request with a limit out of range or a bad
// cursor, including a cursor reused with other filters.
var ErrInvalidQuery = errors.New("invalid asset query")

// ErrAssetNotFound is an Asset the Customer does not have.
var ErrAssetNotFound = errors.New("asset not found")

type StoredAsset = postgres.StoredAsset

type Filter = postgres.AssetFilter

// Rescorer rescores the open Findings of an Asset from its effective
// Criticality and Exposure.
type Rescorer interface {
	RescoreAsset(ctx context.Context, asset inventory.SourceReference) error
}

type Service struct {
	db       *postgres.DB
	rescorer Rescorer
}

func New(db *postgres.DB, rescorer Rescorer) *Service {
	return &Service{db: db, rescorer: rescorer}
}

// Query selects a page of a Customer's Assets. A zero Limit takes
// DefaultLimit.
type Query struct {
	Limit  int
	Filter Filter
	// Cursor is the NextCursor of the previous page, empty for the first.
	Cursor string
}

// Page is one page of a Customer's Assets.
type Page struct {
	Assets []StoredAsset
	// NextCursor continues after the last Asset, empty on the last page.
	NextCursor string
	// Total counts every Asset matching the filters, ignoring paging.
	Total int
}

// cursor is the sort key of the last Asset of a page and the filters that
// produced it, so a cursor cannot silently continue a different listing.
type cursor struct {
	Name    string    `json:"n"`
	Source  uuid.UUID `json:"s"`
	Record  string    `json:"r"`
	Filters string    `json:"f"`
}

// List lists the Customer's Assets across all its CMDB Sources,
// Disconnected ones included, sorted by name, then CMDB Source, then Record
// ID. A Customer without Assets gets an empty page. It fails with
// ErrInvalidQuery.
func (s *Service) List(ctx context.Context, caller tenancy.User, q Query) (Page, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return Page{}, err
	}
	query := postgres.AssetListQuery{Customer: customer, Filter: q.Filter, Limit: q.Limit}
	if query.Limit == 0 {
		query.Limit = DefaultLimit
	}
	if query.Limit < 1 || query.Limit > MaxLimit {
		return Page{}, fmt.Errorf("%w: limit must be a number from 1 to %d", ErrInvalidQuery, MaxLimit)
	}
	filters, err := canonicalFilters(q.Filter)
	if err != nil {
		return Page{}, err
	}
	if q.Cursor != "" {
		if query.After, err = decodeCursor(q.Cursor, filters); err != nil {
			return Page{}, err
		}
	}
	page, err := postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) (postgres.AssetPage, error) { return tx.ListAssets(ctx, query) })
	if err != nil {
		return Page{}, err
	}
	result := Page{Assets: page.Assets, Total: page.Total}
	if page.More {
		last := page.Assets[len(page.Assets)-1].Asset
		result.NextCursor = encodeCursor(cursor{Name: last.Imported().Name(), Source: uuid.UUID(last.Ref().Source), Record: last.Ref().RecordID, Filters: filters})
	}
	return result, nil
}

// canonicalFilters is the form of f a cursor carries. encoding/json sorts map
// keys, so equal filters give equal strings.
func canonicalFilters(f Filter) (string, error) {
	active := "all"
	if f.Active != nil {
		active = fmt.Sprint(*f.Active)
	}
	b, err := json.Marshal(map[string]any{
		"active": active, "kind": canonical(f.Kind), "criticality": canonical(f.Criticality), "exposure": canonical(f.Exposure),
		"information_classification": canonical(f.InformationClassification), "lifecycle_stage": canonical(f.Lifecycle),
		"area": canonical(f.Area),
	})
	return string(b), err
}

func canonical[T cmp.Ordered](values []T) []T {
	return slices.Compact(slices.Sorted(slices.Values(values)))
}

func encodeCursor(c cursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s, filters string) (*postgres.AssetPosition, error) {
	var c cursor
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err == nil {
		err = json.Unmarshal(raw, &c)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: malformed cursor", ErrInvalidQuery)
	}
	if c.Filters != filters {
		return nil, fmt.Errorf("%w: cursor was issued for other filters", ErrInvalidQuery)
	}
	return &postgres.AssetPosition{
		Name: c.Name,
		Ref:  inventory.SourceReference{Source: inventory.CMDBSourceID(c.Source), RecordID: c.Record},
	}, nil
}
