package news_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"barbackend/internal/business"
	"barbackend/internal/news"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

var published = time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)

func article(title, text string) news.Item {
	return news.Item{ID: "report--a", Feed: "bleepingcomputer", Kind: stixext.NewsArticle, Title: title, Text: text, Published: published}
}

func leakPost(victim news.Victim, attacker string) news.Item {
	return news.Item{ID: "report--l", Feed: "ransomwarelive", Kind: stixext.NewsLeakPost, Title: victim.Name, Attacker: attacker, Victims: []news.Victim{victim}, Published: published}
}

// profile is a Mexican payments company with one open Finding and FortiOS on
// its firewalls.
func profile() news.Profile {
	return news.Profile{
		Context: business.Fields{
			Profile:   business.Profile{Sectors: []business.Sector{"financial-services"}},
			Geography: business.Geography{Countries: []string{"MX"}},
			Footprint: business.Footprint{
				Domains: []string{"pagosrapidos.mx"}, Brands: []string{"PagosRápidos"},
				Technologies: []string{"Salesforce"}, ThirdParties: []string{"Nube Contable"},
			},
			Risk: business.Risk{Concerns: []business.Concern{"ransomware"}},
		},
		OpenFindings: map[string][]string{"CVE-2026-1001": {"fw-01", "fw-02"}},
		Products:     []news.ProductUse{{Vendor: "fortinet", Product: "fortios", Assets: []string{"fw-01"}}},
	}
}

func TestRelateNamesTheCustomerByDomainOrBrand(t *testing.T) {
	byDomain := leakPost(news.Victim{Name: "Pagos Rapidos", Domain: "portal.pagosrapidos.mx"}, "Akira")
	match, ok := news.Relate(byDomain, nil, profile())
	if !ok || match.Relevance != news.Named {
		t.Fatalf("Relate = %+v, %v; want named", match, ok)
	}
	if want := "La víctima, «Pagos Rapidos», usa su dominio pagosrapidos.mx."; match.Reasons[0].Text != want {
		t.Errorf("reason = %q, want %q", match.Reasons[0].Text, want)
	}

	byBrand := leakPost(news.Victim{Name: "PagosRápidos S.A. de C.V."}, "Akira")
	if match, _ := news.Relate(byBrand, nil, profile()); match.Relevance != news.Named {
		t.Errorf("a victim named after the brand with its legal suffix is %q, want named", match.Relevance)
	}

	other := leakPost(news.Victim{Name: "Pagos Rapidísimos", Domain: "notpagosrapidos.mx"}, "Akira")
	if match, ok := news.Relate(other, nil, profile()); ok {
		t.Errorf("a lookalike victim matched as %+v", match)
	}
}

func TestRelateFindsOpenFindingsFromTextAndReading(t *testing.T) {
	item := article("Fortinet patches FortiOS flaw", "Attackers exploit CVE-2026-1001 in the wild against FortiOS SSL-VPN.")
	item.CVEs = []string{"CVE-2026-1001"}
	reading := &news.Reading{Vulnerabilities: []news.Vulnerability{{CVE: "CVE-2026-1001", Exploited: true, Quote: "Attackers exploit CVE-2026-1001 in the wild"}}}

	match, ok := news.Relate(item, reading, profile())
	if !ok || match.Relevance != news.Finding {
		t.Fatalf("Relate = %+v, %v; want finding", match, ok)
	}
	want := "Menciona CVE-2026-1001, abierta en 2 Assets: fw-01 y fw-02. La noticia dice que se explota activamente."
	if match.Reasons[0].Text != want {
		t.Errorf("reason = %q, want %q", match.Reasons[0].Text, want)
	}
}

func TestRelateFootprintByProductTechnologyAndThirdParty(t *testing.T) {
	item := article("Campaign targets FortiOS and Salesforce tenants", "A supplier, Nube Contable, was also breached.")
	reading := &news.Reading{Products: []news.Product{{Name: "FortiOS", Vendor: "fortinet", Product: "fortios", Quote: "Campaign targets FortiOS"}}}

	match, ok := news.Relate(item, reading, profile())
	if !ok || match.Relevance != news.Footprint {
		t.Fatalf("Relate = %+v, %v; want footprint", match, ok)
	}
	got := texts(match.Reasons)
	want := []string{
		"Menciona FortiOS, que corre en fw-01.",
		"Menciona «Salesforce», una de las tecnologías de su contexto empresarial.",
		"Menciona a «Nube Contable», uno de sus terceros.",
	}
	if !slices.Equal(got, want) {
		t.Errorf("reasons = %q, want %q", got, want)
	}
}

func TestRelateDoesNotMatchPartsOfWords(t *testing.T) {
	p := profile()
	p.Context.Footprint.Technologies = []string{"SAP"}
	item := article("Sapphire Sleet phishing wave", "The group used fake job offers.")
	if match, ok := news.Relate(item, nil, p); ok {
		t.Errorf("SAP matched inside Sapphire: %+v", match)
	}
}

func TestRelatePeerIsContextAndSharesCountryFirst(t *testing.T) {
	victim := news.Victim{Name: "Banco del Bajío", Sectors: []business.Sector{"financial-services"}, Countries: []string{"MX"}}
	match, ok := news.Relate(leakPost(victim, "RansomHub"), nil, profile())
	if !ok || match.Relevance != news.Peer || !match.SharesCountry {
		t.Fatalf("Relate = %+v, %v; want a peer that shares a country", match, ok)
	}
	want := "Ataque a «Banco del Bajío» (MX), de su sector: servicios financieros. Opera en uno de sus países. Es un tipo de ataque que les preocupa: ransomware y extorsión."
	if match.Reasons[0].Text != want {
		t.Errorf("reason = %q, want %q", match.Reasons[0].Text, want)
	}

	entry := news.Entry{Item: leakPost(victim, "RansomHub"), Match: match}
	labels := entry.Labels()
	if !slices.Contains(labels, news.PeerLabel) || !slices.Contains(labels, news.LeakClaimLabel("RansomHub")) {
		t.Errorf("labels = %q, want the peer and leak-claim labels", labels)
	}
}

func TestRelateWithoutSectorsHasNoPeers(t *testing.T) {
	p := profile()
	p.Context.Profile.Sectors = nil
	victim := news.Victim{Name: "Banco del Bajío", Sectors: []business.Sector{"financial-services"}}
	if match, ok := news.Relate(leakPost(victim, "RansomHub"), nil, p); ok {
		t.Errorf("a Customer with no sector got %+v", match)
	}
}

func TestRelateKeepsEveryReasonClosestFirst(t *testing.T) {
	item := article("Bank hit through CVE-2026-1001", "RansomHub hit Banco Uno, a bank, through CVE-2026-1001.")
	item.CVEs = []string{"CVE-2026-1001"}
	reading := &news.Reading{Attacks: []news.Attack{{Victim: "Banco Uno", Sectors: []business.Sector{"financial-services"}, Attacker: "RansomHub", Quote: "RansomHub hit Banco Uno, a bank"}}}
	match, _ := news.Relate(item, reading, profile())
	if match.Relevance != news.Finding || len(match.Reasons) != 2 || match.Reasons[1].Relevance != news.Peer {
		t.Errorf("Relate = %+v, want finding first and the peer reason kept", match)
	}
}

func TestOrderClosestFirstThenPeersOfTheCountryThenNewest(t *testing.T) {
	older, newer := published.Add(-time.Hour), published
	entries := []news.Entry{
		{Item: news.Item{ID: "peer-old-abroad", Published: newer}, Match: news.Match{Relevance: news.Peer}},
		{Item: news.Item{ID: "peer-home", Published: older}, Match: news.Match{Relevance: news.Peer, SharesCountry: true}},
		{Item: news.Item{ID: "footprint", Published: older}, Match: news.Match{Relevance: news.Footprint}},
		{Item: news.Item{ID: "named", Published: older}, Match: news.Match{Relevance: news.Named}},
	}
	var got []string
	for _, e := range news.Order(entries) {
		got = append(got, e.Item.ID)
	}
	if want := []string{"named", "footprint", "peer-home", "peer-old-abroad"}; !slices.Equal(got, want) {
		t.Errorf("Order = %q, want %q", got, want)
	}
}

func TestOrderKeepsAtMostMaxDigest(t *testing.T) {
	entries := make([]news.Entry, news.MaxDigest+5)
	for i := range entries {
		entries[i] = news.Entry{Match: news.Match{Relevance: news.Peer}}
	}
	entries[len(entries)-1].Match.Relevance = news.Named
	got := news.Order(entries)
	if len(got) != news.MaxDigest || got[0].Match.Relevance != news.Named {
		t.Errorf("Order kept %d, first %q; want %d with named first", len(got), got[0].Match.Relevance, news.MaxDigest)
	}
}

func TestVerifyReadingAcceptsQuotesOfTheItem(t *testing.T) {
	item := article("Akira hits Banco Uno", "The Akira gang claims it stole 40 GB from Banco Uno, a Mexican bank,\nexploiting CVE-2026-1001 in FortiOS.")
	r := news.Reading{
		Summary:         "Akira dice haber robado 40 GB a Banco Uno, banco mexicano, explotando CVE-2026-1001 en FortiOS.",
		Attacks:         []news.Attack{{Victim: "Banco Uno", Sectors: []business.Sector{"financial-services"}, Countries: []string{"MX"}, Kind: "ransomware", Attacker: "Akira", Quote: "The Akira gang claims it stole 40 GB from Banco Uno"}},
		Vulnerabilities: []news.Vulnerability{{CVE: "CVE-2026-1001", Quote: "exploiting  CVE-2026-1001 in FortiOS"}},
		Products:        []news.Product{{Name: "FortiOS", Vendor: "fortinet", Product: "fortios", Quote: "CVE-2026-1001 in FortiOS"}},
	}
	if problems := news.VerifyReading(item, r); len(problems) > 0 {
		t.Errorf("VerifyReading = %q, want none", problems)
	}
}

func TestVerifyReadingRejectsWhatTheItemDoesNotSay(t *testing.T) {
	item := article("Akira hits Banco Uno", "The Akira gang claims it stole 40 GB from Banco Uno.")
	r := news.Reading{
		Summary: "Más en https://example.com",
		Attacks: []news.Attack{
			{Victim: "Banco Dos", Attacker: "Akira", Sectors: []business.Sector{"banking"}, Countries: []string{"Mexico"}, Kind: "extortion", Quote: "The Akira gang claims it stole 40 GB"},
			{Quote: "claims it stole 40 GB"},
		},
		Vulnerabilities: []news.Vulnerability{{CVE: "CVE-2026-9999", Quote: "The Akira gang claims"}},
		Products:        []news.Product{{Name: "FortiOS", Vendor: "Fortinet Inc", Quote: "Invented quote of the item"}},
	}
	problems := strings.Join(news.VerifyReading(item, r), "\n")
	for _, want := range []string{
		"summary has a URL",
		`attacks[0].victim "Banco Dos" is not in its quote`,
		`"banking", which is not a sector code`,
		`"Mexico", which is not an ISO 3166-1 alpha-2 code`,
		`kind is "extortion"`,
		"attacks[1] names no victim and no sector",
		`vulnerabilities[0].cve "CVE-2026-9999" is not in its quote`,
		"products[0].quote",
		`products[0].vendor "Fortinet Inc" is not a CPE token`,
	} {
		if !strings.Contains(problems, want) {
			t.Errorf("problems lack %q:\n%s", want, problems)
		}
	}
}

func TestVerifyEditorialChecksKeysFillerCVEsAndEvidence(t *testing.T) {
	entries := []news.Entry{
		{Item: news.Item{ID: "a", CVEs: []string{"CVE-2026-1001"}}, Match: news.Match{Relevance: news.Finding}},
		{Item: news.Item{ID: "b"}, Match: news.Match{Relevance: news.Peer}},
	}
	context := map[string]any{"operations": map[string]any{"critical_services": []any{map[string]any{"name": "Pagos en línea"}}}}

	good := news.Editorial{Items: []news.EditorialItem{
		{Key: "n2", Why: "Contexto del sector: otro banco mexicano perdió datos de clientes."},
		{Key: "n1", Why: "CVE-2026-1001 está abierta en los firewalls que protegen Pagos en línea.", ContextEvidence: []news.ContextEvidence{{Path: "/operations/critical_services/0/name", Value: "Pagos en línea"}}},
	}}
	if problems := news.VerifyEditorial(entries, good, context); len(problems) > 0 {
		t.Errorf("VerifyEditorial = %q, want none", problems)
	}

	bad := news.Editorial{Items: []news.EditorialItem{
		{Key: "n1", Why: "Es importante mantenerse alerta ante CVE-2026-2002.", ContextEvidence: []news.ContextEvidence{{Path: "/operations/critical_services/3/name", Value: "x"}}},
		{Key: "n1", Why: "Repetido."},
		{Key: "n9", Why: "No existe."},
	}}
	problems := strings.Join(news.VerifyEditorial(entries, bad, context), "\n")
	for _, want := range []string{`"es importante"`, "names CVE-2026-2002", `path "/operations/critical_services/3/name" is not in the business context`, `"n1" appears twice`, `"n9" is not a news item`, `news item "n2" has no item`} {
		if !strings.Contains(problems, want) {
			t.Errorf("problems lack %q:\n%s", want, problems)
		}
	}
}

func TestApplyOrdersWithinARelevanceOnly(t *testing.T) {
	entries := []news.Entry{
		{Item: news.Item{ID: "f"}, Match: news.Match{Relevance: news.Finding}},
		{Item: news.Item{ID: "p1"}, Match: news.Match{Relevance: news.Peer}},
		{Item: news.Item{ID: "p2"}, Match: news.Match{Relevance: news.Peer}},
	}
	// The Editor puts a peer first and swaps the peers: only the swap holds.
	e := news.Editorial{Items: []news.EditorialItem{{Key: "n3", Why: "tres"}, {Key: "n2", Why: "dos"}, {Key: "n1", Why: "uno"}}}
	var got []string
	for _, edited := range news.Apply(entries, e) {
		got = append(got, edited.Item.ID+":"+edited.Why)
	}
	if want := []string{"f:uno", "p2:tres", "p1:dos"}; !slices.Equal(got, want) {
		t.Errorf("Apply = %q, want %q", got, want)
	}
	// Without an Editorial, the rules' order stands and no item has a why.
	for i, edited := range news.Apply(entries, news.Editorial{}) {
		if edited.Item.ID != entries[i].Item.ID || edited.Why != "" {
			t.Errorf("Apply without an editorial moved or explained %q", edited.Item.ID)
		}
	}
}

func TestItemFromReadsTheReportAndItsVictims(t *testing.T) {
	victim, err := stix2.NewIdentity("Banco Uno",
		stix2.OptionClass("organization"), stix2.OptionSectors([]string{"financial-services", "not-a-sector"}),
		stix2.OptionExtension(string(stixext.VictimDefinitionID), stixext.NewVictim(stixext.Victim{Countries: []string{"MX"}, Domain: "bancouno.mx"})),
	)
	if err != nil {
		t.Fatal(err)
	}
	victim.ID = stixext.VictimID("bancouno.mx", "", "")
	r, err := stix2.NewReport("Banco Uno", &stix2.Timestamp{Time: published},
		[]stix2.Identifier{victim.ID, stixext.VulnerabilityID("CVE-2026-1001")},
		stix2.OptionDescription("Stolen through CVE-2026-1001 and CVE-2026-1002."),
		stix2.OptionExtension(string(stixext.NewsDefinitionID), stixext.NewNews(stixext.News{Feed: "ransomwarelive", Kind: stixext.NewsLeakPost, Attacker: "Akira", Link: "https://example.org/p"})),
	)
	if err != nil {
		t.Fatal(err)
	}
	// Through JSON, as stored.
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded stix2.Report
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	item, err := news.ItemFrom(&decoded, []*stix2.Identity{victim})
	if err != nil {
		t.Fatal(err)
	}
	if !item.IsLeakPost() || item.Attacker != "Akira" || !item.Published.Equal(published) {
		t.Errorf("item = %+v", item)
	}
	if !slices.Equal(item.CVEs, []string{"CVE-2026-1001"}) {
		t.Errorf("CVEs = %q, want only the one it refers to", item.CVEs)
	}
	want := news.Victim{Name: "Banco Uno", Domain: "bancouno.mx", Sectors: []business.Sector{"financial-services"}, Countries: []string{"MX"}}
	if len(item.Victims) != 1 || item.Victims[0].Name != want.Name || item.Victims[0].Domain != want.Domain ||
		!slices.Equal(item.Victims[0].Sectors, want.Sectors) || !slices.Equal(item.Victims[0].Countries, want.Countries) {
		t.Errorf("victims = %+v, want %+v", item.Victims, want)
	}

	plain, err := stix2.NewReport("not news", &stix2.Timestamp{Time: published}, []stix2.Identifier{stixext.BarbattackID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := news.ItemFrom(plain, nil); err == nil {
		t.Error("a report without news/1 is a News Item")
	}
}

func texts(reasons []news.Reason) []string {
	out := make([]string, len(reasons))
	for i, r := range reasons {
		out[i] = r.Text
	}
	return out
}
