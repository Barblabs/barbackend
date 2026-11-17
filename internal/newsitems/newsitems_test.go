package newsitems_test

import (
	"context"
	"testing"
	"time"

	"barbackend/internal/newsitems"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

func newDB(t *testing.T) *postgres.DB {
	t.Helper()
	db, err := postgres.Open(context.Background(), pgtest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

func report(t *testing.T, key string, refs []stix2.Identifier, ext *stixext.News) *stix2.Report {
	t.Helper()
	opts := []stix2.STIXOption{stix2.OptionDescription("Exploited: CVE-2026-1001.")}
	if ext != nil {
		opts = append(opts, stix2.OptionExtension(string(stixext.NewsDefinitionID), stixext.NewNews(*ext)))
	}
	r, err := stix2.NewReport(key, &stix2.Timestamp{Time: time.Now().Add(-time.Hour)}, refs, opts...)
	if err != nil {
		t.Fatal(err)
	}
	r.ID = stixext.ID(stix2.TypeReport, key)
	return r
}

func TestHandleNewsStoresNewsItemsAndTheirVictims(t *testing.T) {
	t.Parallel()
	db := newDB(t)
	victim, err := stix2.NewIdentity("Banco Uno", stix2.OptionClass("organization"))
	if err != nil {
		t.Fatal(err)
	}
	victim.ID = stixext.VictimID("bancouno.mx", "", "")
	leak := report(t, "leak", []stix2.Identifier{victim.ID}, &stixext.News{Feed: "ransomwarelive", Kind: stixext.NewsLeakPost, Attacker: "Akira"})
	article := report(t, "article", []stix2.Identifier{stixext.VulnerabilityID("CVE-2026-1001")}, &stixext.News{Feed: "bleepingcomputer", Kind: stixext.NewsArticle})
	advisory := report(t, "advisory", []stix2.Identifier{stixext.VulnerabilityID("CVE-2026-1001")}, nil)

	ctx := context.Background()
	if err := newsitems.New(db).HandleNews(ctx, []stix2.STIXObject{victim, leak, article, advisory}); err != nil {
		t.Fatal(err)
	}

	var ready []postgres.ReadyNewsItem
	var unread []postgres.UnreadArticle
	err = db.InTx(ctx, func(tx *postgres.Tx) (err error) {
		if ready, err = tx.ReadyNewsItems(ctx, time.Now().Add(-time.Hour), time.Now().Add(time.Minute)); err != nil {
			return err
		}
		unread, err = tx.UnreadArticles(ctx, time.Now().Add(-24*time.Hour), 10, 3)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ready) != 1 || ready[0].ID != string(leak.ID) || len(ready[0].Victims) != 1 {
		t.Errorf("ready = %+v, want the leak post with its victim", ready)
	}
	if len(unread) != 1 || unread[0].ID != string(article.ID) {
		t.Errorf("unread = %+v, want the article, and no report without news/1", unread)
	}
}
