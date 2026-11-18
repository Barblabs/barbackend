package httpapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"barbackend/internal/claude/claudetest"
	"barbackend/internal/news"
	"barbackend/internal/newsitems"
	"barbackend/internal/stixext"
	"barbackend/internal/tenancy"
	"github.com/TcM1911/stix2"
	"github.com/google/uuid"
)

type newsDigestBody struct {
	ID                     string `json:"id"`
	BusinessContextVersion *int   `json:"business_context_version"`
	NoSectors              bool   `json:"no_sectors"`
	Counts                 struct {
		Named, Finding, Footprint, Peer int
	} `json:"counts"`
	Editor struct {
		Status string `json:"status"`
	} `json:"editor"`
	Groups []struct {
		Relevance string `json:"relevance"`
		Items     []struct {
			NewsItemID string   `json:"news_item_id"`
			Kind       string   `json:"kind"`
			Title      string   `json:"title"`
			Link       string   `json:"link"`
			Summary    *string  `json:"summary"`
			Excerpt    *string  `json:"excerpt"`
			Labels     []string `json:"labels"`
			Reasons    []string `json:"reasons"`
			Why        *string  `json:"why"`
			Attacks    []struct {
				Victim    string   `json:"victim"`
				Sectors   []string `json:"sectors"`
				Countries []string `json:"countries"`
				Attacker  *string  `json:"attacker"`
			} `json:"attacks"`
		} `json:"items"`
	} `json:"groups"`
}

// digestPeerNews stores a leak post on a Mexican bank, states that the
// Customer is a bank, and has the Editor write its digest.
func (e env) digestPeerNews(t *testing.T) {
	t.Helper()
	victim, err := stix2.NewIdentity("Banco del Bajío", stix2.OptionClass("organization"), stix2.OptionSectors([]string{"financial-services"}),
		stix2.OptionExtension(string(stixext.VictimDefinitionID), stixext.NewVictim(stixext.Victim{Countries: []string{"MX"}})))
	if err != nil {
		t.Fatal(err)
	}
	victim.ID = stixext.VictimID("", "ransomwarelive", "bb")
	r, err := stix2.NewReport("Banco del Bajío <b>leak</b>", &stix2.Timestamp{Time: time.Now().Add(-time.Hour)}, []stix2.Identifier{victim.ID},
		stix2.OptionDescription("Data: 200 GB."),
		stix2.OptionExtension(string(stixext.NewsDefinitionID), stixext.NewNews(stixext.News{Feed: "ransomwarelive", Kind: stixext.NewsLeakPost, Attacker: "RansomHub", Link: "https://example.org/leak"})))
	if err != nil {
		t.Fatal(err)
	}
	r.ID = stixext.ID(stix2.TypeReport, "ransomwarelive:bb")
	if err := newsitems.New(e.db).HandleNews(context.Background(), []stix2.STIXObject{victim, r}); err != nil {
		t.Fatal(err)
	}
	_, admin := e.customerAdmin(t, e.customer)
	fields := contextFields("Banco.")
	fields["profile"].(map[string]any)["sectors"] = []string{"financial-services"}
	save := map[string]any{"version": 0, "context": fields}
	if rec := e.asUser(admin, http.MethodPut, "/business-context", save); rec.Code != http.StatusOK {
		t.Fatalf("save business context = %d %s", rec.Code, rec.Body)
	}
	e.llm.Queue(claudetest.JSON(t, news.Editorial{Items: []news.EditorialItem{{Key: "n1", Why: "Otro banco mexicano fue extorsionado: contexto del sector."}}}))
	if err := e.agents.DigestNews(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNewsDigestLifecycle(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.digestPeerNews(t)

	list := decode[struct {
		NewsDigests []struct {
			ID     string             `json:"id"`
			Counts struct{ Peer int } `json:"counts"`
		} `json:"news_digests"`
	}](t, e.do(httptest.NewRequest(http.MethodGet, "/news-digests", nil)), http.StatusOK)
	if len(list.NewsDigests) != 1 || list.NewsDigests[0].Counts.Peer != 1 {
		t.Fatalf("list = %+v, want one digest with one peer", list)
	}

	got := decode[newsDigestBody](t, e.do(httptest.NewRequest(http.MethodGet, "/news-digests/"+list.NewsDigests[0].ID, nil)), http.StatusOK)
	if got.Editor.Status != "verified" || got.BusinessContextVersion == nil || *got.BusinessContextVersion != 1 || got.NoSectors {
		t.Errorf("digest = %+v", got)
	}
	if len(got.Groups) != 1 || got.Groups[0].Relevance != "peer" || len(got.Groups[0].Items) != 1 {
		t.Fatalf("groups = %+v, want one peer", got.Groups)
	}
	item := got.Groups[0].Items[0]
	if item.Kind != "leak_post" || item.Title != "Banco del Bajío <b>leak</b>" || item.Why == nil || item.Summary != nil || item.Excerpt == nil || *item.Excerpt != "Data: 200 GB." {
		t.Errorf("item = %+v", item)
	}
	if len(item.Labels) != 2 || !strings.Contains(strings.Join(item.Labels, " "), "es contexto, no indica que ustedes estén expuestos") {
		t.Errorf("labels = %q, want the leak claim and the peer label", item.Labels)
	}
	if len(item.Attacks) != 1 || item.Attacks[0].Victim != "Banco del Bajío" || item.Attacks[0].Attacker == nil || *item.Attacks[0].Attacker != "RansomHub" {
		t.Errorf("attacks = %+v", item.Attacks)
	}
}

func TestNewsDigestErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.digestPeerNews(t)

	missing := e.do(httptest.NewRequest(http.MethodGet, "/news-digests/"+uuid.NewString(), nil))
	if missing.Code != http.StatusNotFound || !strings.Contains(missing.Body.String(), `"code":"news_digest_not_found"`) {
		t.Errorf("a missing digest = %d %s, want 404 news_digest_not_found", missing.Code, missing.Body)
	}
	if rec := e.do(httptest.NewRequest(http.MethodGet, "/news-digests?limit=0", nil)); rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
		t.Errorf("limit 0 = %d, want it refused", rec.Code)
	}

	stranger := "Bearer " + e.signIn(t, e.newUser(t, tenancy.Viewer, e.newCustomer(t)))
	list := decode[struct {
		NewsDigests []struct{ ID string } `json:"news_digests"`
	}](t, e.as(stranger, httptest.NewRequest(http.MethodGet, "/news-digests", nil)), http.StatusOK)
	if len(list.NewsDigests) != 0 {
		t.Errorf("another Customer lists %d digests", len(list.NewsDigests))
	}
}
