package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"barbackend/internal/postgres/sqlcgen"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// StoredNewsItem is a News Item as its Feed emitted it (ADR 0025): its STIX
// report is opaque here, and its use case decodes it.
type StoredNewsItem struct {
	ID        string
	Feed      string
	Kind      string
	Published time.Time
	CVEs      []string
	Object    json.RawMessage
	Modified  time.Time
	// Ready is whether it can go in a News Digest on receipt: a leak post,
	// which comes with its victim, while an article waits for the Reader.
	Ready bool
	// Victims are the STIX ids of the victims it refers to.
	Victims []string
}

// StoredVictim is a victim a structured Feed names, as its STIX identity.
type StoredVictim struct {
	ID     string
	Object json.RawMessage
}

// StoreNews stores victims, then items, each replacing the one its Feed
// published before, and links each item to the stored victims it refers to.
func (t *Tx) StoreNews(ctx context.Context, items []StoredNewsItem, victims []StoredVictim) error {
	for _, v := range victims {
		if err := t.q.UpsertNewsVictim(ctx, sqlcgen.UpsertNewsVictimParams{ID: v.ID, Object: v.Object}); err != nil {
			return fmt.Errorf("store news victim %s: %w", v.ID, err)
		}
	}
	for _, n := range items {
		if err := t.q.UpsertNewsItem(ctx, sqlcgen.UpsertNewsItemParams{
			ID: n.ID, Feed: n.Feed, Kind: n.Kind, PublishedAt: n.Published, CveIds: nonNil(n.CVEs),
			Object: n.Object, ModifiedAt: n.Modified, Ready: n.Ready,
		}); err != nil {
			return fmt.Errorf("store news item %s: %w", n.ID, err)
		}
		if len(n.Victims) == 0 {
			continue
		}
		if err := t.q.LinkNewsVictims(ctx, sqlcgen.LinkNewsVictimsParams{NewsItemID: n.ID, VictimIds: n.Victims}); err != nil {
			return fmt.Errorf("link news item %s to its victims: %w", n.ID, err)
		}
	}
	return nil
}

// UnreadArticle is an article the Reader has yet to read.
type UnreadArticle struct {
	ID     string
	Object json.RawMessage
}

// UnreadArticles is at most limit articles published since a moment that
// have no reading, or a failed one of fewer than maxAttempts attempts, newest
// first.
func (t *Tx) UnreadArticles(ctx context.Context, since time.Time, limit, maxAttempts int) ([]UnreadArticle, error) {
	rows, err := t.q.ListUnreadArticles(ctx, sqlcgen.ListUnreadArticlesParams{
		PublishedSince: since, MaxAttempts: int32(maxAttempts), MaxItems: int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("list unread articles: %w", err)
	}
	out := make([]UnreadArticle, len(rows))
	for i, row := range rows {
		out[i] = UnreadArticle{ID: row.ID, Object: row.Object}
	}
	return out, nil
}

// ErrRead is a News Item whose reading is already final.
var ErrRead = errors.New("news item already read")

// StoreReading stores the Reader's final reading of a News Item, content, and
// makes the item ready for News Digests. It fails with ErrRead when the item
// already has a final reading.
func (t *Tx) StoreReading(ctx context.Context, id, model, promptID string, content json.RawMessage) error {
	if _, err := t.recordReading(ctx, id, "read", model, promptID, content); err != nil {
		return err
	}
	return t.markReady(ctx, id)
}

// StoreFailedReading records a failed attempt to read a News Item. Once it has
// failed maxAttempts times the item goes in News Digests unread, with what its
// Feed gave. It fails with ErrRead when the item already has a final reading.
func (t *Tx) StoreFailedReading(ctx context.Context, id, model, promptID string, maxAttempts int) error {
	attempts, err := t.recordReading(ctx, id, "failed", model, promptID, nil)
	if err != nil || attempts < maxAttempts {
		return err
	}
	return t.markReady(ctx, id)
}

func (t *Tx) recordReading(ctx context.Context, id, outcome, model, promptID string, content json.RawMessage) (int, error) {
	attempts, err := t.q.RecordReading(ctx, sqlcgen.RecordReadingParams{
		NewsItemID: id, Outcome: outcome, Model: model, PromptID: promptID, Content: content,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("news item %s: %w", id, ErrRead)
	}
	if err != nil {
		return 0, fmt.Errorf("record reading of %s: %w", id, err)
	}
	return int(attempts), nil
}

func (t *Tx) markReady(ctx context.Context, id string) error {
	if err := t.q.MarkNewsItemReady(ctx, id); err != nil {
		return fmt.Errorf("make news item %s ready: %w", id, err)
	}
	return nil
}

// ReadingsSince is how many readings had their last attempt at or after since.
func (t *Tx) ReadingsSince(ctx context.Context, since time.Time) (int, error) {
	n, err := t.q.CountReadingsSince(ctx, since)
	if err != nil {
		return 0, fmt.Errorf("count readings since %s: %w", since.Format(time.RFC3339), err)
	}
	return int(n), nil
}

// ReadyNewsItem is a News Item ready for News Digests, with the Reader's
// reading, nil when it has none, and its victims.
type ReadyNewsItem struct {
	ID      string
	Object  json.RawMessage
	Reading json.RawMessage
	Victims []json.RawMessage
}

// ReadyNewsItems is the News Items that became ready in (since, until],
// newest first.
func (t *Tx) ReadyNewsItems(ctx context.Context, since, until time.Time) ([]ReadyNewsItem, error) {
	rows, err := t.q.ListReadyNewsItems(ctx, sqlcgen.ListReadyNewsItemsParams{Since: &since, Until: &until})
	if err != nil {
		return nil, fmt.Errorf("list ready news items: %w", err)
	}
	out := make([]ReadyNewsItem, len(rows))
	ids := make([]string, len(rows))
	index := make(map[string]int, len(rows))
	for i, row := range rows {
		out[i] = ReadyNewsItem{ID: row.ID, Object: row.Object, Reading: row.Reading}
		ids[i], index[row.ID] = row.ID, i
	}
	if len(ids) == 0 {
		return out, nil
	}
	victims, err := t.q.ListVictimsOfNewsItems(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("list victims of news items: %w", err)
	}
	for _, v := range victims {
		i := index[v.NewsItemID]
		out[i].Victims = append(out[i].Victims, v.Object)
	}
	return out, nil
}

// NewsProfile is what a Customer's News Items are matched with, besides its
// Business Context: its open Findings and the Products its Active Assets run.
type NewsProfile struct {
	// OpenFindings is, by CVE ID, the names of the Assets of its open
	// Findings.
	OpenFindings map[string][]string
	// Products is, by CPE vendor and product tokens, the names of the Active
	// Assets that run them.
	Products map[[2]string][]string
}

// NewsProfile reads the Customer's open Findings and the Products of its
// Active Assets.
func (t *Tx) NewsProfile(ctx context.Context, customer tenancy.CustomerID) (NewsProfile, error) {
	findings, err := t.q.ListOpenFindingCVEsOfCustomer(ctx, uuid.UUID(customer))
	if err != nil {
		return NewsProfile{}, fmt.Errorf("list open finding cves of %s: %w", customer, err)
	}
	products, err := t.q.ListProductsOfCustomer(ctx, uuid.UUID(customer))
	if err != nil {
		return NewsProfile{}, fmt.Errorf("list products of %s: %w", customer, err)
	}
	p := NewsProfile{OpenFindings: map[string][]string{}, Products: map[[2]string][]string{}}
	for _, f := range findings {
		p.OpenFindings[f.CveID] = append(p.OpenFindings[f.CveID], f.AssetName)
	}
	for _, c := range products {
		key := [2]string{c.ProductVendor, c.ProductName}
		p.Products[key] = append(p.Products[key], c.AssetName)
	}
	return p, nil
}

// NewsDigest is one News Digest of a Customer. Content is what its use case
// wrote; it is opaque here.
type NewsDigest struct {
	ID       uuid.UUID
	Customer tenancy.CustomerID
	Since    time.Time
	Until    time.Time
	// BusinessContext is the version of the Business Context it read, 0 when
	// the Customer had stated none.
	BusinessContext int
	Counts          NewsCounts
	Content         json.RawMessage
	Created         time.Time
}

// NewsCounts is how many News Items a digest holds of each Relevance.
type NewsCounts struct {
	Named, Finding, Footprint, Peer int
}

// StoreNewsDigest stores d.
func (t *Tx) StoreNewsDigest(ctx context.Context, d NewsDigest) error {
	if err := t.q.InsertNewsDigest(ctx, sqlcgen.InsertNewsDigestParams{
		ID: d.ID, CustomerID: uuid.UUID(d.Customer), Since: d.Since, Until: d.Until,
		BusinessContextVersion: int32(d.BusinessContext),
		NamedCount:             int32(d.Counts.Named), FindingCount: int32(d.Counts.Finding),
		FootprintCount: int32(d.Counts.Footprint), PeerCount: int32(d.Counts.Peer),
		Content: d.Content,
	}); err != nil {
		return fmt.Errorf("store news digest of %s: %w", d.Customer, err)
	}
	return nil
}

// LatestNewsDigestUntil is when the Customer's newest News Digest ends, and
// false when it has none.
func (t *Tx) LatestNewsDigestUntil(ctx context.Context, customer tenancy.CustomerID) (time.Time, bool, error) {
	until, err := t.q.LatestNewsDigestUntil(ctx, uuid.UUID(customer))
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("read latest news digest of %s: %w", customer, err)
	}
	return until, true, nil
}

// NewsDigests is at most limit of the Customer's News Digests, newest first,
// without their content.
func (t *Tx) NewsDigests(ctx context.Context, customer tenancy.CustomerID, limit int) ([]NewsDigest, error) {
	rows, err := t.q.ListNewsDigests(ctx, sqlcgen.ListNewsDigestsParams{CustomerID: uuid.UUID(customer), MaxDigests: int32(limit)})
	if err != nil {
		return nil, fmt.Errorf("list news digests of %s: %w", customer, err)
	}
	out := make([]NewsDigest, len(rows))
	for i, row := range rows {
		out[i] = NewsDigest{
			ID: row.ID, Customer: customer, Since: row.Since, Until: row.Until, Created: row.CreatedAt,
			Counts: NewsCounts{Named: int(row.NamedCount), Finding: int(row.FindingCount), Footprint: int(row.FootprintCount), Peer: int(row.PeerCount)},
		}
	}
	return out, nil
}

// NewsDigest is one of the Customer's News Digests. It fails with ErrNotFound
// when the Customer has no digest of that id.
func (t *Tx) NewsDigest(ctx context.Context, customer tenancy.CustomerID, id uuid.UUID) (NewsDigest, error) {
	row, err := t.q.GetNewsDigest(ctx, sqlcgen.GetNewsDigestParams{CustomerID: uuid.UUID(customer), ID: id})
	if errors.Is(err, pgx.ErrNoRows) {
		return NewsDigest{}, fmt.Errorf("news digest %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return NewsDigest{}, fmt.Errorf("get news digest %s: %w", id, err)
	}
	return NewsDigest{
		ID: row.ID, Customer: customer, Since: row.Since, Until: row.Until, Created: row.CreatedAt,
		BusinessContext: int(row.BusinessContextVersion), Content: row.Content,
		Counts: NewsCounts{Named: int(row.NamedCount), Finding: int(row.FindingCount), Footprint: int(row.FootprintCount), Peer: int(row.PeerCount)},
	}, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
