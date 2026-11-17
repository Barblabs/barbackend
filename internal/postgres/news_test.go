package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"github.com/google/uuid"
)

const (
	articleID = "report--1a2b7c1e-3f4d-5e6f-8a9b-0c1d2e3f4a51"
	leakID    = "report--1a2b7c1e-3f4d-5e6f-8a9b-0c1d2e3f4a52"
	victimID  = "identity--1a2b7c1e-3f4d-5e6f-8a9b-0c1d2e3f4a53"
)

func newsItem(id, kind string, published time.Time, victims ...string) postgres.StoredNewsItem {
	return postgres.StoredNewsItem{
		ID: id, Feed: "feed", Kind: kind, Published: published, CVEs: []string{"CVE-2026-0001"},
		Object:   json.RawMessage(fmt.Sprintf(`{"type":"report","id":%q}`, id)),
		Modified: published, Ready: kind == "leak_post", Victims: victims,
	}
}

func storeNews(t *testing.T, db *postgres.DB, items []postgres.StoredNewsItem, victims ...postgres.StoredVictim) {
	t.Helper()
	inTx(t, db, func(tx *postgres.Tx) error { return tx.StoreNews(context.Background(), items, victims) })
}

func unread(t *testing.T, db *postgres.DB) []string {
	t.Helper()
	articles := inTxValue(t, db, func(tx *postgres.Tx) ([]postgres.UnreadArticle, error) {
		return tx.UnreadArticles(context.Background(), time.Now().Add(-7*24*time.Hour), 10, 3)
	})
	var ids []string
	for _, a := range articles {
		ids = append(ids, a.ID)
	}
	return ids
}

func ready(t *testing.T, db *postgres.DB, since time.Time) []postgres.ReadyNewsItem {
	t.Helper()
	return inTxValue(t, db, func(tx *postgres.Tx) ([]postgres.ReadyNewsItem, error) {
		return tx.ReadyNewsItems(context.Background(), since, time.Now().Add(time.Minute))
	})
}

func TestStoreNewsMakesLeakPostsReadyAndArticlesWaitForTheReader(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	now := time.Now().UTC()
	victim := postgres.StoredVictim{ID: victimID, Object: json.RawMessage(fmt.Sprintf(`{"type":"identity","id":%q,"name":"Banco Uno"}`, victimID))}
	storeNews(t, db, []postgres.StoredNewsItem{newsItem(articleID, "article", now), newsItem(leakID, "leak_post", now, victimID)}, victim)

	got := ready(t, db, now.Add(-time.Hour))
	if len(got) != 1 || got[0].ID != leakID || len(got[0].Victims) != 1 || got[0].Reading != nil {
		t.Fatalf("ready = %+v, want only the leak post with its victim", got)
	}
	if ids := unread(t, db); !slices.Equal(ids, []string{articleID}) {
		t.Errorf("unread = %q, want the article", ids)
	}

	// Stored again, as a Feed publishes it again: still once, still ready.
	storeNews(t, db, []postgres.StoredNewsItem{newsItem(leakID, "leak_post", now, victimID)}, victim)
	if got := ready(t, db, now.Add(-time.Hour)); len(got) != 1 {
		t.Errorf("ready after storing again = %d items, want 1", len(got))
	}
}

func TestReadingMakesAnArticleReadyOnce(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	now := time.Now().UTC()
	storeNews(t, db, []postgres.StoredNewsItem{newsItem(articleID, "article", now)})

	ctx := context.Background()
	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.StoreReading(ctx, articleID, "m", "p", json.RawMessage(`{"summary":"x"}`))
	})
	got := ready(t, db, now.Add(-time.Hour))
	if len(got) != 1 || string(got[0].Reading) != `{"summary": "x"}` {
		t.Fatalf("ready = %+v, want the article with its reading", got)
	}
	if ids := unread(t, db); len(ids) != 0 {
		t.Errorf("unread = %q, want none", ids)
	}
	err := db.InTx(ctx, func(tx *postgres.Tx) error {
		return tx.StoreReading(ctx, articleID, "m", "p", json.RawMessage(`{"summary":"y"}`))
	})
	if !errors.Is(err, postgres.ErrRead) {
		t.Errorf("reading a read article again = %v, want ErrRead", err)
	}
	if n := inTxValue(t, db, func(tx *postgres.Tx) (int, error) { return tx.ReadingsSince(ctx, now.Add(-time.Hour)) }); n != 1 {
		t.Errorf("ReadingsSince = %d, want 1", n)
	}
}

func TestFailedReadingsMakeAnArticleReadyUnreadOnceAttemptsRunOut(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	now := time.Now().UTC()
	storeNews(t, db, []postgres.StoredNewsItem{newsItem(articleID, "article", now)})
	ctx := context.Background()
	fail := func() {
		inTx(t, db, func(tx *postgres.Tx) error { return tx.StoreFailedReading(ctx, articleID, "m", "p", 2) })
	}

	fail()
	if len(ready(t, db, now.Add(-time.Hour))) != 0 || len(unread(t, db)) != 1 {
		t.Fatal("after one failure the article should wait for another attempt")
	}
	fail()
	got := ready(t, db, now.Add(-time.Hour))
	if len(got) != 1 || got[0].Reading != nil {
		t.Fatalf("after the last attempt ready = %+v, want the article without a reading", got)
	}
}

func TestUnreadArticlesLeavesOutOldNews(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	storeNews(t, db, []postgres.StoredNewsItem{newsItem(articleID, "article", time.Now().Add(-30*24*time.Hour))})
	if ids := unread(t, db); len(ids) != 0 {
		t.Errorf("unread = %q, want none older than the window", ids)
	}
}

func TestNewsProfileReadsOpenFindingsAndProductsOfActiveAssets(t *testing.T) {
	t.Parallel()
	w := newFindingWorld(t)
	saveMatch(t, w.db, match(t, w.payments, "1.20.0"))

	p := inTxValue(t, w.db, func(tx *postgres.Tx) (postgres.NewsProfile, error) {
		return tx.NewsProfile(context.Background(), w.customer)
	})
	if got := p.OpenFindings["CVE-2021-23017"]; !slices.Equal(got, []string{"payments"}) {
		t.Errorf("open findings of CVE-2021-23017 = %q, want payments", got)
	}
	if got := p.Products[[2]string{"f5", "nginx"}]; !slices.Equal(got, []string{"lab", "payments"}) {
		t.Errorf("assets running f5 nginx = %q, want lab and payments", got)
	}

	other := newCustomer(t, w.db)
	empty := inTxValue(t, w.db, func(tx *postgres.Tx) (postgres.NewsProfile, error) {
		return tx.NewsProfile(context.Background(), other)
	})
	if len(empty.OpenFindings) != 0 || len(empty.Products) != 0 {
		t.Errorf("another Customer's profile = %+v, want nothing of the first", empty)
	}
}

func TestNewsDigestsAreTheCustomersOnly(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	customer, other := newCustomer(t, db), newCustomer(t, db)
	ctx := context.Background()
	day := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	d := postgres.NewsDigest{
		ID: uuid.New(), Customer: customer, Since: day.Add(-24 * time.Hour), Until: day, BusinessContext: 2,
		Counts: postgres.NewsCounts{Finding: 1, Peer: 3}, Content: json.RawMessage(`{"entries":[]}`),
	}
	inTx(t, db, func(tx *postgres.Tx) error { return tx.StoreNewsDigest(ctx, d) })

	until, ok := inTxValue2(t, db, func(tx *postgres.Tx) (time.Time, bool, error) { return tx.LatestNewsDigestUntil(ctx, customer) })
	if !ok || !until.Equal(day) {
		t.Errorf("LatestNewsDigestUntil = %s, %v; want %s", until, ok, day)
	}
	if _, ok := inTxValue2(t, db, func(tx *postgres.Tx) (time.Time, bool, error) { return tx.LatestNewsDigestUntil(ctx, other) }); ok {
		t.Error("another Customer has a latest digest")
	}

	list := inTxValue(t, db, func(tx *postgres.Tx) ([]postgres.NewsDigest, error) { return tx.NewsDigests(ctx, customer, 10) })
	if len(list) != 1 || list[0].ID != d.ID || list[0].Counts != d.Counts {
		t.Errorf("NewsDigests = %+v, want the stored one", list)
	}
	got := inTxValue(t, db, func(tx *postgres.Tx) (postgres.NewsDigest, error) { return tx.NewsDigest(ctx, customer, d.ID) })
	if got.BusinessContext != 2 || string(got.Content) != `{"entries": []}` {
		t.Errorf("NewsDigest = %+v", got)
	}
	err := db.InTx(ctx, func(tx *postgres.Tx) error {
		_, err := tx.NewsDigest(ctx, other, d.ID)
		return err
	})
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("another Customer reading the digest = %v, want ErrNotFound", err)
	}
}

func inTxValue2[A, B any](t *testing.T, db *postgres.DB, fn func(*postgres.Tx) (A, B, error)) (A, B) {
	t.Helper()
	var a A
	var b B
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		a, b, err = fn(tx)
		return err
	})
	return a, b
}
