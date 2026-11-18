package agents_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"barbackend/internal/agents"
	"barbackend/internal/business"
	"barbackend/internal/claude/claudetest"
	"barbackend/internal/news"
	"barbackend/internal/newsitems"
	"barbackend/internal/postgres"
	"barbackend/internal/stixext"
	"barbackend/internal/tenancy"
	"github.com/TcM1911/stix2"
)

const (
	articleTitle = "PostgreSQL servers hijacked to mine crypto"
	articleText  = "Attackers are brute-forcing exposed PostgreSQL servers to deploy cryptominers, researchers said on Monday."
)

// storeArticle stores, through the news Feed handler, an article about
// PostgreSQL, which the Customer's Asset runs.
func storeArticle(t *testing.T, e env) string {
	t.Helper()
	r, err := stix2.NewReport(articleTitle, &stix2.Timestamp{Time: time.Now().Add(-time.Hour)}, []stix2.Identifier{stixext.BarbattackID},
		stix2.OptionDescription(articleText),
		stix2.OptionExtension(string(stixext.NewsDefinitionID), stixext.NewNews(stixext.News{Feed: "bleepingcomputer", Kind: stixext.NewsArticle, Language: "en", Link: "https://example.org/pg"})),
	)
	if err != nil {
		t.Fatal(err)
	}
	r.ID = stixext.ID(stix2.TypeReport, "bleepingcomputer:pg")
	if err := newsitems.New(e.db).HandleNews(context.Background(), []stix2.STIXObject{r}); err != nil {
		t.Fatal(err)
	}
	return string(r.ID)
}

// storeLeakPost stores a leak post claiming a Mexican bank.
func storeLeakPost(t *testing.T, e env) string {
	t.Helper()
	victim, err := stix2.NewIdentity("Banco del Bajío",
		stix2.OptionClass("organization"), stix2.OptionSectors([]string{"financial-services"}),
		stix2.OptionExtension(string(stixext.VictimDefinitionID), stixext.NewVictim(stixext.Victim{Countries: []string{"MX"}, Domain: "bb.mx"})),
	)
	if err != nil {
		t.Fatal(err)
	}
	victim.ID = stixext.VictimID("bb.mx", "ransomwarelive", "")
	r, err := stix2.NewReport("Banco del Bajío", &stix2.Timestamp{Time: time.Now().Add(-2 * time.Hour)}, []stix2.Identifier{victim.ID},
		stix2.OptionDescription("Data: 200 GB."),
		stix2.OptionExtension(string(stixext.NewsDefinitionID), stixext.NewNews(stixext.News{Feed: "ransomwarelive", Kind: stixext.NewsLeakPost, Attacker: "RansomHub", Link: "https://example.org/leak"})),
	)
	if err != nil {
		t.Fatal(err)
	}
	r.ID = stixext.ID(stix2.TypeReport, "ransomwarelive:bb")
	if err := newsitems.New(e.db).HandleNews(context.Background(), []stix2.STIXObject{victim, r}); err != nil {
		t.Fatal(err)
	}
	return string(r.ID)
}

func pgReading() news.Reading {
	return news.Reading{
		Summary:  "Atacantes adivinan contraseñas de servidores PostgreSQL expuestos para instalar mineros de criptomonedas.",
		Products: []news.Product{{Name: "PostgreSQL", Vendor: "postgresql", Product: "postgresql", Quote: "brute-forcing exposed PostgreSQL servers"}},
	}
}

func saveContext(t *testing.T, e env, fields business.Fields) {
	t.Helper()
	bc, err := business.New(fields)
	if err != nil {
		t.Fatal(err)
	}
	err = e.db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.SaveBusinessContext(context.Background(), e.customer, 0, bc, e.user)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func bankContext() business.Fields {
	return business.Fields{
		Profile:   business.Profile{Sectors: []business.Sector{"financial-services"}},
		Geography: business.Geography{Countries: []string{"MX"}},
		Operations: business.Operations{CriticalServices: []business.CriticalService{
			{Name: "Pagos en línea", Impact: "critical", MaxDowntime: "1h_4h", Assets: []string{"pg-prod-01"}},
		}},
		Risk: business.Risk{Concerns: []business.Concern{"ransomware"}},
	}
}

func TestReadNewsStoresAVerifiedReadingAfterOneRetry(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	storeArticle(t, e)
	wrong := pgReading()
	wrong.Products[0].Quote = "a quote the article does not hold"
	e.llm.Queue(claudetest.JSON(t, wrong), claudetest.JSON(t, pgReading()))

	run, err := e.svc.ReadNews(context.Background())
	if err != nil || run.Read != 1 || run.Failed != 0 {
		t.Fatalf("ReadNews = %+v, %v; want one read", run, err)
	}
	requests := e.llm.Requests()
	if len(requests) != 2 || !strings.Contains(requestText(requests[1]), "<rejected>") {
		t.Errorf("the retry was not told what was wrong: %d requests", len(requests))
	}
	if again, _ := e.svc.ReadNews(context.Background()); again.Read != 0 {
		t.Errorf("a read article was read again: %+v", again)
	}
}

func TestReadNewsSpendsNoAttemptWhenTheModelIsUnavailable(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	storeArticle(t, e)
	e.llm.Queue(claudetest.Fail(http.StatusInternalServerError), claudetest.Fail(http.StatusInternalServerError),
		claudetest.Fail(http.StatusInternalServerError), claudetest.Fail(http.StatusInternalServerError))

	if _, err := e.svc.ReadNews(context.Background()); !errors.Is(err, agents.ErrUnavailable) {
		t.Fatalf("ReadNews = %v, want ErrUnavailable", err)
	}
	e.llm.Queue(claudetest.JSON(t, pgReading()))
	if run, err := e.svc.ReadNews(context.Background()); err != nil || run.Read != 1 {
		t.Errorf("after the outage ReadNews = %+v, %v; want the article read", run, err)
	}
}

func TestDigestNewsGroupsByRelevanceWithTheEditorsReasons(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	saveContext(t, e, bankContext())
	article := storeArticle(t, e)
	leak := storeLeakPost(t, e)
	e.llm.Queue(claudetest.JSON(t, pgReading()))
	if _, err := e.svc.ReadNews(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.llm.Queue(claudetest.JSON(t, news.Editorial{Items: []news.EditorialItem{
		{Key: "n2", Why: "Otro banco mexicano, del mismo sector, fue extorsionado con ransomware: es contexto."},
		{Key: "n1", Why: "pg-prod-01 corre PostgreSQL y sostiene Pagos en línea; revisen si acepta conexiones desde internet.",
			ContextEvidence: []news.ContextEvidence{{Path: "/operations/critical_services/0/name", Value: "Pagos en línea"}}},
	}}))

	if err := e.svc.DigestNews(context.Background()); err != nil {
		t.Fatal(err)
	}
	d := latestDigest(t, e, e.user)
	if d.Editor.Status != agents.Verified || d.BusinessContext != 1 || d.NoSectors {
		t.Fatalf("digest = %+v", d)
	}
	if d.Counts != (postgres.NewsCounts{Footprint: 1, Peer: 1}) {
		t.Errorf("counts = %+v", d.Counts)
	}
	footprint, peer := d.Entries[0], d.Entries[1]
	if footprint.NewsItem != article || footprint.Relevance != news.Footprint || footprint.Summary == "" || !strings.HasPrefix(footprint.Why, "pg-prod-01") {
		t.Errorf("first entry = %+v, want the footprint article with its summary and why", footprint)
	}
	if want := "Menciona PostgreSQL, que corre en pg-prod-01."; footprint.Reasons[0].Text != want {
		t.Errorf("footprint reason = %q, want %q", footprint.Reasons[0].Text, want)
	}
	if peer.NewsItem != leak || peer.Relevance != news.Peer || !slices.Contains(peer.Labels, news.PeerLabel) || !slices.Contains(peer.Labels, news.LeakClaimLabel("RansomHub")) {
		t.Errorf("second entry = %+v, want the peer leak post with both labels", peer)
	}

	requests := e.llm.Requests()
	editor := requestText(requests[len(requests)-1])
	if !strings.Contains(editor, "<business_context>") || !strings.Contains(editor, "Pagos en línea") {
		t.Error("the Editor did not read the Business Context")
	}

	// Within a day there is no second digest.
	if err := e.svc.DigestNews(context.Background()); err != nil {
		t.Fatal(err)
	}
	if list, _ := e.svc.NewsDigests(context.Background(), e.user, 0); len(list) != 1 {
		t.Errorf("digests = %d, want 1", len(list))
	}
}

func TestDigestNewsKeepsTheRulesOrderWhenTheEditorFails(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	saveContext(t, e, bankContext())
	storeLeakPost(t, e)
	e.llm.Queue(claudetest.Refusal())

	if err := e.svc.DigestNews(context.Background()); err != nil {
		t.Fatal(err)
	}
	d := latestDigest(t, e, e.user)
	if d.Editor.Status != agents.Refused || len(d.Entries) != 1 || d.Entries[0].Why != "" || d.Entries[0].Relevance != news.Peer {
		t.Errorf("digest = %+v, want the peer without a why", d)
	}
}

func TestDigestNewsSkipsCustomersNothingIsRelevantTo(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	// No sector stated: a leak post on a bank is no Peer of this Customer.
	storeLeakPost(t, e)
	if err := e.svc.DigestNews(context.Background()); err != nil {
		t.Fatal(err)
	}
	if list, _ := e.svc.NewsDigests(context.Background(), e.user, 0); len(list) != 0 {
		t.Errorf("digests = %+v, want none", list)
	}
	if n := len(e.llm.Requests()); n != 0 {
		t.Errorf("the Editor was called %d times for nothing", n)
	}
}

func latestDigest(t *testing.T, e env, user tenancy.User) agents.NewsDigest {
	t.Helper()
	list, err := e.svc.NewsDigests(context.Background(), user, 1)
	if err != nil || len(list) != 1 {
		t.Fatalf("NewsDigests = %+v, %v; want one", list, err)
	}
	d, err := e.svc.GetNewsDigest(context.Background(), user, list[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// requestText is the text of a request's last user message.
func requestText(r claudetest.Request) string {
	messages, _ := r["messages"].([]any)
	if len(messages) == 0 {
		return ""
	}
	last, _ := messages[len(messages)-1].(map[string]any)
	var b strings.Builder
	switch content := last["content"].(type) {
	case string:
		b.WriteString(content)
	case []any:
		for _, block := range content {
			if m, ok := block.(map[string]any); ok {
				text, _ := m["text"].(string)
				b.WriteString(text)
			}
		}
	}
	return b.String()
}
