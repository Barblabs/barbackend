package news

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"barbackend/internal/business"
	"barbackend/internal/stixext"
)

// Limits on what the Reader states of one News Item.
const (
	MaxSummary         = 280
	MaxAttacks         = 5
	MaxVulnerabilities = 10
	MaxProducts        = 8
	minQuote           = 12
)

// Reading is what the Reader states of one News Item (ADR 0025): a summary for
// people, and, each with a quote of the item, the Reported Attacks it reports,
// what it says about Vulnerabilities and the Products it names. It reads no
// Customer's data, so a Reading is the same for every Customer.
type Reading struct {
	// Summary says in one sentence, in Spanish, what happened.
	Summary         string          `json:"summary"`
	Attacks         []Attack        `json:"attacks"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Products        []Product       `json:"products"`
}

// Attack is a Reported Attack as the Reader states it: the source's claim,
// never confirmed.
type Attack struct {
	// Victim is the organization as the item names it, blank when it names
	// none, as in "hospitals in Germany".
	Victim    string            `json:"victim"`
	Sectors   []business.Sector `json:"sectors"`
	Countries []string          `json:"countries"`
	// Kind is the kind of attack, a code of business.Concerns(), blank when
	// the item does not say.
	Kind     business.Concern `json:"kind"`
	Attacker string           `json:"attacker"`
	Quote    string           `json:"quote"`
}

// Vulnerability is what the item says of one CVE.
type Vulnerability struct {
	CVE string `json:"cve"`
	// Exploited is whether the item says it is exploited in the wild.
	Exploited bool   `json:"exploited"`
	Quote     string `json:"quote"`
}

// Product is a Product the item names, as written and as the CPE vendor and
// product tokens the Reader takes it to be (ADR 0019), blank when it cannot
// tell.
type Product struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Quote   string `json:"quote"`
}

var (
	urlPattern      = regexp.MustCompile(`(?i)\b(https?://|www\.)\S+`)
	cpeTokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.\-]*$`)
)

// VerifyReading checks r against the item it reads, without a model: every
// quote is the item's own words, every victim, attacker, CVE and Product is in
// its quote, and every code is one a Business Context can state. It cannot
// judge a sector, a country or a CPE token inferred from a quote.
func VerifyReading(item Item, r Reading) []string {
	source := normalized(item.Title + "\n" + item.Text)
	var problems []string
	problems = append(problems, checkSummary(r.Summary)...)
	if len(r.Attacks) > MaxAttacks {
		problems = append(problems, fmt.Sprintf("states %d attacks, more than %d", len(r.Attacks), MaxAttacks))
	}
	if len(r.Vulnerabilities) > MaxVulnerabilities {
		problems = append(problems, fmt.Sprintf("states %d vulnerabilities, more than %d", len(r.Vulnerabilities), MaxVulnerabilities))
	}
	if len(r.Products) > MaxProducts {
		problems = append(problems, fmt.Sprintf("states %d products, more than %d", len(r.Products), MaxProducts))
	}
	for i, a := range r.Attacks {
		problems = append(problems, checkAttack(fmt.Sprintf("attacks[%d]", i), a, source)...)
	}
	for i, v := range r.Vulnerabilities {
		problems = append(problems, checkVulnerability(fmt.Sprintf("vulnerabilities[%d]", i), v, source)...)
	}
	for i, p := range r.Products {
		problems = append(problems, checkProduct(fmt.Sprintf("products[%d]", i), p, source)...)
	}
	return problems
}

func checkSummary(s string) []string {
	switch {
	case strings.TrimSpace(s) == "":
		return []string{"summary is blank"}
	case utf8.RuneCountInString(s) > MaxSummary:
		return []string{fmt.Sprintf("summary is longer than %d characters", MaxSummary)}
	case urlPattern.MatchString(s):
		return []string{"summary has a URL"}
	}
	return nil
}

func checkAttack(field string, a Attack, source string) []string {
	problems := checkQuote(field, a.Quote, source)
	problems = append(problems, inQuote(field+".victim", a.Victim, a.Quote)...)
	problems = append(problems, inQuote(field+".attacker", a.Attacker, a.Quote)...)
	if a.Victim == "" && len(a.Sectors) == 0 {
		problems = append(problems, field+" names no victim and no sector")
	}
	for _, s := range a.Sectors {
		if !slices.Contains(business.Sectors(), s) {
			problems = append(problems, fmt.Sprintf("%s.sectors has %q, which is not a sector code", field, s))
		}
	}
	for _, c := range a.Countries {
		if !business.IsCountry(c) {
			problems = append(problems, fmt.Sprintf("%s.countries has %q, which is not an ISO 3166-1 alpha-2 code", field, c))
		}
	}
	if a.Kind != "" && !slices.Contains(business.Concerns(), a.Kind) {
		problems = append(problems, fmt.Sprintf("%s.kind is %q, which is not a kind of attack", field, a.Kind))
	}
	return problems
}

func checkVulnerability(field string, v Vulnerability, source string) []string {
	problems := checkQuote(field, v.Quote, source)
	cve, ok := stixext.CVEID(v.CVE)
	if !ok {
		return append(problems, fmt.Sprintf("%s.cve %q is not a CVE ID", field, v.CVE))
	}
	return append(problems, inQuote(field+".cve", cve, v.Quote)...)
}

func checkProduct(field string, p Product, source string) []string {
	problems := checkQuote(field, p.Quote, source)
	if strings.TrimSpace(p.Name) == "" {
		problems = append(problems, field+".name is blank")
	}
	problems = append(problems, inQuote(field+".name", p.Name, p.Quote)...)
	for _, token := range [][2]string{{"vendor", p.Vendor}, {"product", p.Product}} {
		if token[1] != "" && !cpeTokenPattern.MatchString(token[1]) {
			problems = append(problems, fmt.Sprintf("%s.%s %q is not a CPE token: lowercase, without spaces", field, token[0], token[1]))
		}
	}
	return problems
}

func checkQuote(field, quote, source string) []string {
	q := normalized(quote)
	switch {
	case utf8.RuneCountInString(q) < minQuote:
		return []string{fmt.Sprintf("%s.quote is shorter than %d characters", field, minQuote)}
	case !strings.Contains(source, q):
		return []string{fmt.Sprintf("%s.quote %q is not in the news item's title or text", field, quote)}
	}
	return nil
}

func inQuote(field, value, quote string) []string {
	if strings.TrimSpace(value) == "" || strings.Contains(normalized(quote), normalized(value)) {
		return nil
	}
	return []string{fmt.Sprintf("%s %q is not in its quote", field, value)}
}

// normalized is s lowercased, with typographic quotes and dashes as plain ones
// and whitespace collapsed, so a quote matches whatever spacing it was copied
// with.
func normalized(s string) string {
	return strings.Join(strings.Fields(typography.Replace(strings.ToLower(s))), " ")
}

var typography = strings.NewReplacer("‘", "'", "’", "'", "“", `"`, "”", `"`, "–", "-", "—", "-", " ", " ")
