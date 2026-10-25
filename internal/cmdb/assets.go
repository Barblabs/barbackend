package cmdb

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"github.com/google/uuid"
)

const (
	defaultAssetLimit = 50
	maxAssetLimit     = 200
)

// ErrInvalidAssetQuery is an asset list request with a bad limit, filter or
// cursor, including a cursor reused with other filters.
var ErrInvalidAssetQuery = errors.New("invalid asset query")

type (
	ListedAsset = postgres.ListedAsset
	OwnerValue  = postgres.OwnerValue
)

// AssetQuery is an asset list request as a client wrote it. Empty fields
// take their defaults.
type AssetQuery struct {
	Limit       string
	Cursor      string
	Active      string
	Kind        string
	Criticality string
}

// AssetPage is one page of a Customer's Assets.
type AssetPage struct {
	Assets []ListedAsset
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

// ListAssets lists the Customer's Assets across all its CMDB Sources,
// Disconnected ones included, sorted by name, then CMDB Source, then Record
// ID. It hides Inactive Assets unless q.Active says otherwise. A Customer
// without Assets gets an empty page. It fails with ErrInvalidAssetQuery.
func (s *Service) ListAssets(ctx context.Context, customer inventory.CustomerID, q AssetQuery) (AssetPage, error) {
	query, filters, err := parseAssetQuery(q)
	if err != nil {
		return AssetPage{}, err
	}
	query.Customer = customer
	if q.Cursor != "" {
		if query.After, err = decodeCursor(q.Cursor, filters); err != nil {
			return AssetPage{}, err
		}
	}
	var page postgres.AssetPage
	err = s.db.InTx(ctx, func(tx *postgres.Tx) (err error) {
		page, err = tx.ListAssets(ctx, query)
		return err
	})
	if err != nil {
		return AssetPage{}, err
	}
	result := AssetPage{Assets: page.Assets, Total: page.Total}
	if page.More {
		last := page.Assets[len(page.Assets)-1]
		result.NextCursor = encodeCursor(cursor{Name: last.Name, Source: uuid.UUID(last.Ref.Source), Record: last.Ref.RecordID, Filters: filters})
	}
	return result, nil
}

// parseAssetQuery also returns the canonical form of the filters, which a
// cursor carries.
func parseAssetQuery(q AssetQuery) (query postgres.AssetListQuery, filters string, err error) {
	query.Limit = defaultAssetLimit
	if q.Limit != "" {
		query.Limit, err = strconv.Atoi(q.Limit)
		if err != nil || query.Limit < 1 || query.Limit > maxAssetLimit {
			return query, "", fmt.Errorf("%w: limit must be a number from 1 to %d", ErrInvalidAssetQuery, maxAssetLimit)
		}
	}
	active := q.Active
	switch active {
	case "":
		active = "true"
		fallthrough
	case "true":
		query.Active = ptr(true)
	case "false":
		query.Active = ptr(false)
	case "all":
	default:
		return query, "", fmt.Errorf("%w: active must be true, false or all", ErrInvalidAssetQuery)
	}
	if q.Kind != "" {
		kind, err := inventory.ParseAssetKind(q.Kind)
		if err != nil {
			return query, "", fmt.Errorf("%w: unknown kind %q", ErrInvalidAssetQuery, q.Kind)
		}
		query.Kind = &kind
	}
	if q.Criticality != "" {
		criticality, err := inventory.ParseCriticality(q.Criticality)
		if err != nil {
			return query, "", fmt.Errorf("%w: unknown criticality %q", ErrInvalidAssetQuery, q.Criticality)
		}
		query.Criticality = &criticality
	}
	filters, err = canonicalJSON(map[string]string{"active": active, "kind": q.Kind, "criticality": q.Criticality})
	return query, filters, err
}

// canonicalJSON relies on encoding/json sorting map keys.
func canonicalJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
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
		return nil, fmt.Errorf("%w: malformed cursor", ErrInvalidAssetQuery)
	}
	if c.Filters != filters {
		return nil, fmt.Errorf("%w: cursor was issued for other filters", ErrInvalidAssetQuery)
	}
	return &postgres.AssetPosition{
		Name: c.Name,
		Ref:  inventory.SourceReference{Source: inventory.CMDBSourceID(c.Source), RecordID: c.Record},
	}, nil
}

func ptr[T any](v T) *T { return &v }
