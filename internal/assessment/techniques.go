package assessment

import (
	"fmt"
	"html"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

// htmlTag is an HTML tag, such as those of an AWS Security Bulletin.
var htmlTag = regexp.MustCompile(`<[^>]*>`)

// MaxTechniques is how many Techniques the Cartógrafo may label one
// Vulnerability with (ADR 0024).
const MaxTechniques = 5

// The roles of a Technique in an attack on a Vulnerability: how it is
// exploited, what that gives the attacker directly, and what they can do
// next with that.
const (
	RoleExploitation    = "exploitation"
	RolePrimaryImpact   = "primary_impact"
	RoleSecondaryImpact = "secondary_impact"
)

// Roles are the roles a Technique label may have.
func Roles() []string { return []string{RoleExploitation, RolePrimaryImpact, RoleSecondaryImpact} }

// LabelingInput is what the Cartógrafo reads of one Vulnerability: what
// tells how it is exploited and what it gives, and nothing of a Customer.
type LabelingInput struct {
	CVE              string          `json:"cve"`
	Description      string          `json:"description"`
	CWEs             []string        `json:"cwes"`
	CVSSVectors      []string        `json:"cvss_vectors"`
	AffectedProducts []string        `json:"affected_products"`
	KEV              *KEVFacts       `json:"kev"`
	Advisories       []AdvisoryFacts `json:"advisories"`
}

// KEVFacts is what CISA's KEV catalog says of how a Vulnerability is used.
type KEVFacts struct {
	RequiredAction             string `json:"required_action"`
	KnownRansomwareCampaignUse string `json:"known_ransomware_campaign_use"`
}

// AdvisoryFacts is an Advisory linked to the Vulnerability (ADR 0022).
type AdvisoryFacts struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

// NewLabelingInput reads v, a stored Vulnerability with the extensions of
// every Feed, and its Advisories, as plain text: a Feed such as AWS's writes
// HTML, whose tags cost tokens and tell nothing. The products are those its
// numbering authority names, or NVD's CPE matches when it names none.
func NewLabelingInput(v *stix2.Vulnerability, advisories []AdvisoryFacts) LabelingInput {
	in := LabelingInput{
		CVE: v.Name, Description: v.Description,
		CWEs: []string{}, CVSSVectors: []string{}, AffectedProducts: []string{},
		Advisories: make([]AdvisoryFacts, len(advisories)),
	}
	for i, a := range advisories {
		in.Advisories[i] = AdvisoryFacts{Title: plainText(a.Title), Description: plainText(a.Description)}
	}
	if nvd, ok := stixext.NVDOf(v); ok {
		in.CWEs = append(in.CWEs, nvd.CWEs...)
		for _, m := range nvd.CVSS {
			in.CVSSVectors = appendNew(in.CVSSVectors, m.Vector)
		}
		for _, a := range nvd.CNAAffected {
			in.AffectedProducts = appendNew(in.AffectedProducts, strings.TrimSpace(a.Vendor+" "+a.Product))
		}
		if len(nvd.CNAAffected) == 0 {
			for _, a := range nvd.Affected {
				in.AffectedProducts = appendNew(in.AffectedProducts, a.Vendor+" "+a.Product)
			}
		}
	}
	if kev, ok := stixext.KEVOf(v); ok {
		in.KEV = &KEVFacts{RequiredAction: kev.RequiredAction, KnownRansomwareCampaignUse: kev.KnownRansomwareCampaignUse}
	}
	return in
}

// plainText is s without its HTML tags and entities, and with each run of
// spaces made one, keeping its line breaks.
func plainText(s string) string {
	lines := strings.Split(html.UnescapeString(htmlTag.ReplaceAllString(s, " ")), "\n")
	kept := lines[:0]
	for _, line := range lines {
		if line = strings.Join(strings.Fields(line), " "); line != "" {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

func appendNew(values []string, v string) []string {
	if v == "" || slices.Contains(values, v) {
		return values
	}
	return append(values, v)
}

// TechniqueLabels is the Cartógrafo's output: the Techniques a Vulnerability
// maps to, or none when what it says is not enough to tell.
type TechniqueLabels struct {
	Techniques []TechniqueLabel `json:"techniques"`
}

// TechniqueLabel is one Technique of a Vulnerability, by its ATT&CK id, with
// its role, an exact quote of the input that supports it, and why it fits.
type TechniqueLabel struct {
	AttackID  string `json:"attack_id"`
	Role      string `json:"role"`
	Evidence  string `json:"evidence"`
	Rationale string `json:"rationale"`
}

// VerifyTechniqueLabels returns every way l relies on something in was not
// given, none when it holds: at most MaxTechniques, each a Technique of
// offered by its ATT&CK id and labeled once, with a known role, evidence that
// quotes in, ignoring case and spacing, and no URL. It cannot tell whether a
// Technique is right.
func VerifyTechniqueLabels(in LabelingInput, offered []string, l TechniqueLabels) []string {
	var violations []string
	if len(l.Techniques) > MaxTechniques {
		violations = append(violations, fmt.Sprintf("gives %d techniques, more than %d", len(l.Techniques), MaxTechniques))
	}
	sources := in.quotable()
	seen := map[string]bool{}
	for i, t := range l.Techniques {
		label := fmt.Sprintf("technique %d (%s)", i+1, t.AttackID)
		if !slices.Contains(offered, t.AttackID) {
			violations = append(violations, label+": is not a technique of the catalog")
		}
		if seen[t.AttackID] {
			violations = append(violations, label+": is labeled twice")
		}
		seen[t.AttackID] = true
		if !slices.Contains(Roles(), t.Role) {
			violations = append(violations, fmt.Sprintf("%s: role %q is not one of %v", label, t.Role, Roles()))
		}
		violations = append(violations, checkQuote(label, t.Evidence, sources)...)
		if strings.TrimSpace(t.Rationale) == "" {
			violations = append(violations, label+": gives no rationale")
		}
		if urlPattern.MatchString(t.Evidence) || urlPattern.MatchString(t.Rationale) {
			violations = append(violations, label+": writes a URL")
		}
	}
	return violations
}

func checkQuote(label, evidence string, sources []string) []string {
	quote := normalized(evidence)
	if utf8.RuneCountInString(quote) < minQuote {
		return []string{fmt.Sprintf("%s: evidence %q is shorter than %d characters", label, evidence, minQuote)}
	}
	if !slices.ContainsFunc(sources, func(s string) bool { return strings.Contains(s, quote) }) {
		return []string{fmt.Sprintf("%s: evidence %q is not an exact quote of the description, the kev fields or an advisory", label, evidence)}
	}
	return nil
}

// quotable is each text evidence may quote, normalized.
func (in LabelingInput) quotable() []string {
	texts := []string{in.Description}
	if in.KEV != nil {
		texts = append(texts, in.KEV.RequiredAction)
	}
	for _, a := range in.Advisories {
		texts = append(texts, a.Title, a.Description)
	}
	for i, t := range texts {
		texts[i] = normalized(t)
	}
	return texts
}

// normalized is s in lower case with its spacing collapsed, so a quote that
// wraps a line differently still matches.
func normalized(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}
