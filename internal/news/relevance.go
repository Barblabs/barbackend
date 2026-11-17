package news

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"barbackend/internal/business"
)

// Relevance is why a News Item matters to one Customer. Rules decide it,
// never an Agent, so the same News Item and Customer always get the same one.
type Relevance string

// The Relevances, from closest to farthest.
const (
	// Named is a News Item whose victim is the Customer itself.
	Named Relevance = "named"
	// Finding is one that names the Vulnerability of an open Finding.
	Finding Relevance = "finding"
	// Footprint is one that names a Product its Active Assets run, or a
	// technology or third party its Business Context states.
	Footprint Relevance = "footprint"
	// Peer is an attack on an organization that shares a sector with it:
	// context, never a sign that the Customer is exposed.
	Peer Relevance = "peer"
)

// Relevances are every Relevance, closest first.
func Relevances() []Relevance { return []Relevance{Named, Finding, Footprint, Peer} }

func (r Relevance) rank() int { return slices.Index(Relevances(), r) }

// Profile is what the rules compare a News Item with for one Customer.
type Profile struct {
	Context business.Fields
	// OpenFindings is, by CVE ID, the names of the Assets where it has an
	// open Finding.
	OpenFindings map[string][]string
	// Products are the Products its Active Assets run.
	Products []ProductUse
}

// ProductUse is a Product, by its CPE vendor and product tokens, and the
// names of the Active Assets that run it.
type ProductUse struct {
	Vendor, Product string
	Assets          []string
}

// Reason is one rule a News Item met, in words code writes, never a model.
type Reason struct {
	Relevance Relevance `json:"relevance"`
	Text      string    `json:"text"`
}

// Match is a News Item's Relevance to one Customer, the closest that applies,
// with every reason.
type Match struct {
	Relevance Relevance `json:"relevance"`
	Reasons   []Reason  `json:"reasons"`
	// SharesCountry is whether a victim it reports shares a country with the
	// Customer, which puts a Peer first.
	SharesCountry bool `json:"shares_country"`
}

// Relate is item's Relevance to the Customer of p, and false when it has none
// and does not reach the Customer. reading is nil while the Reader has not
// read item.
func Relate(item Item, reading *Reading, p Profile) (Match, bool) {
	victims := reportedOf(item, reading)
	reasons := slices.Concat(
		named(victims, p.Context.Footprint),
		findings(item, reading, p.OpenFindings),
		footprint(item, reading, victims, p),
	)
	peers, sharesCountry := peers(victims, p.Context)
	reasons = append(reasons, peers...)
	if len(reasons) == 0 {
		return Match{}, false
	}
	slices.SortStableFunc(reasons, func(a, b Reason) int { return cmp.Compare(a.Relevance.rank(), b.Relevance.rank()) })
	return Match{Relevance: reasons[0].Relevance, Reasons: reasons, SharesCountry: sharesCountry}, true
}

// reported is a victim a News Item reports, from its Feed or from the Reader.
type reported struct {
	Victim
	kind     business.Concern
	attacker string
}

func reportedOf(item Item, reading *Reading) []reported {
	var out []reported
	for _, v := range item.Victims {
		r := reported{Victim: v, attacker: item.Attacker}
		if item.IsLeakPost() {
			r.kind = "ransomware"
		}
		out = append(out, r)
	}
	if reading == nil {
		return out
	}
	for _, a := range reading.Attacks {
		out = append(out, reported{
			Victim:   Victim{Name: strings.TrimSpace(a.Victim), Sectors: a.Sectors, Countries: a.Countries},
			kind:     a.Kind,
			attacker: strings.TrimSpace(a.Attacker),
		})
	}
	return out
}

func named(victims []reported, f business.Footprint) []Reason {
	var out []Reason
	for _, v := range victims {
		if d := domainOf(v.Domain, f.Domains); d != "" {
			out = append(out, Reason{Named, fmt.Sprintf("La víctima, «%s», usa su dominio %s.", v.Name, d)})
			continue
		}
		if b := sameName(v.Name, f.Brands); b != "" {
			out = append(out, Reason{Named, fmt.Sprintf("La víctima, «%s», lleva su marca «%s».", v.Name, b)})
		}
	}
	return out
}

// domainOf is the domain of domains that victim is, or is a subdomain of.
func domainOf(victim string, domains []string) string {
	victim = strings.ToLower(strings.TrimSpace(victim))
	if victim == "" {
		return ""
	}
	for _, d := range domains {
		if victim == d || strings.HasSuffix(victim, "."+d) {
			return d
		}
	}
	return ""
}

func findings(item Item, reading *Reading, open map[string][]string) []Reason {
	exploited := map[string]bool{}
	cves := slices.Clone(item.CVEs)
	if reading != nil {
		for _, v := range reading.Vulnerabilities {
			if !slices.Contains(cves, v.CVE) {
				cves = append(cves, v.CVE)
			}
			exploited[v.CVE] = exploited[v.CVE] || v.Exploited
		}
	}
	var out []Reason
	for _, cve := range cves {
		assets, ok := open[cve]
		if !ok {
			continue
		}
		text := fmt.Sprintf("Menciona %s, abierta en %s.", cve, list(assets))
		if exploited[cve] {
			text += " La noticia dice que se explota activamente."
		}
		out = append(out, Reason{Finding, text})
	}
	return out
}

func footprint(item Item, reading *Reading, victims []reported, p Profile) []Reason {
	var out []Reason
	if reading != nil {
		for _, product := range reading.Products {
			if use, ok := runs(product, p.Products); ok {
				out = append(out, Reason{Footprint, fmt.Sprintf("Menciona %s, que corre en %s.", product.Name, list(use.Assets))})
			}
		}
	}
	text := item.Title + "\n" + item.Text
	for _, t := range p.Context.Footprint.Technologies {
		if mentions(text, t) {
			out = append(out, Reason{Footprint, fmt.Sprintf("Menciona «%s», una de las tecnologías de su contexto empresarial.", t)})
		}
	}
	for _, party := range p.Context.Footprint.ThirdParties {
		if victim := victimNamed(victims, party); victim != "" {
			out = append(out, Reason{Footprint, fmt.Sprintf("La víctima, «%s», es uno de sus terceros.", victim)})
		} else if mentions(text, party) {
			out = append(out, Reason{Footprint, fmt.Sprintf("Menciona a «%s», uno de sus terceros.", party)})
		}
	}
	return out
}

func runs(p Product, uses []ProductUse) (ProductUse, bool) {
	if p.Vendor == "" || p.Product == "" {
		return ProductUse{}, false
	}
	for _, use := range uses {
		if strings.EqualFold(use.Vendor, p.Vendor) && strings.EqualFold(use.Product, p.Product) {
			return use, true
		}
	}
	return ProductUse{}, false
}

func victimNamed(victims []reported, party string) string {
	for _, v := range victims {
		if sameName(v.Name, []string{party}) != "" {
			return v.Name
		}
	}
	return ""
}

func peers(victims []reported, c business.Fields) ([]Reason, bool) {
	var out []Reason
	sharesCountry := false
	for _, v := range victims {
		shared := intersect(v.Sectors, c.Profile.Sectors)
		if len(shared) == 0 {
			continue
		}
		country := len(intersect(v.Countries, c.Geography.Countries)) > 0
		sharesCountry = sharesCountry || country
		out = append(out, Reason{Peer, peerText(v, shared, country, c.Risk.Concerns)})
	}
	return out, sharesCountry
}

func peerText(v reported, shared []business.Sector, sharesCountry bool, concerns []business.Concern) string {
	var b strings.Builder
	if v.Name != "" {
		fmt.Fprintf(&b, "Ataque a «%s»", v.Name)
	} else {
		b.WriteString("Ataque a organizaciones")
	}
	if len(v.Countries) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(v.Countries, ", "))
	}
	fmt.Fprintf(&b, ", de su sector: %s.", joinSectors(shared))
	if sharesCountry {
		b.WriteString(" Opera en uno de sus países.")
	}
	if v.kind != "" && slices.Contains(concerns, v.kind) {
		fmt.Fprintf(&b, " Es un tipo de ataque que les preocupa: %s.", ConcernName(v.kind))
	}
	return b.String()
}

func intersect[T comparable](a, b []T) []T {
	var out []T
	for _, x := range a {
		if slices.Contains(b, x) && !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

// list names up to three Assets and counts the rest, as "5 Assets: srv-01,
// srv-02, srv-03 y 2 más".
func list(names []string) string {
	const shown = 3
	switch {
	case len(names) == 1:
		return names[0]
	case len(names) <= shown:
		return fmt.Sprintf("%d Assets: %s y %s", len(names), strings.Join(names[:len(names)-1], ", "), names[len(names)-1])
	default:
		return fmt.Sprintf("%d Assets: %s y %d más", len(names), strings.Join(names[:shown], ", "), len(names)-shown)
	}
}

// mentions reports whether text names term as a whole word, ignoring case.
// A term shorter than 3 characters names nothing: it would match too much.
func mentions(text, term string) bool {
	term = strings.TrimSpace(term)
	if utf8.RuneCountInString(term) < 3 {
		return false
	}
	pattern := `(?i)(^|[^\pL\pN])` + regexp.QuoteMeta(term) + `($|[^\pL\pN])`
	return regexp.MustCompile(pattern).MatchString(text)
}

// sameName is the name of names that is name once case, punctuation and legal
// suffixes are set aside, or blank.
func sameName(name string, names []string) string {
	key := nameKey(name)
	if key == "" {
		return ""
	}
	for _, n := range names {
		if nameKey(n) == key {
			return n
		}
	}
	return ""
}

var legalSuffixes = []string{"sa", "sab", "de", "cv", "rl", "sapi", "sc", "inc", "llc", "ltd", "corp", "corporation", "co", "gmbh", "ag", "plc", "srl", "spa", "bv", "nv", "limited", "company"}

func nameKey(name string) string {
	words := strings.FieldsFunc(strings.ReplaceAll(strings.ToLower(name), ".", ""), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	for len(words) > 1 && slices.Contains(legalSuffixes, words[len(words)-1]) {
		words = words[:len(words)-1]
	}
	return strings.Join(words, " ")
}
