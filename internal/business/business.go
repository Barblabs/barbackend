// Package business is the domain of a Customer's Business Context: what it
// tells barbattack about its business, for the Agents to weigh Findings and
// threats against (ADR 0017).
package business

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Schema names the JSON shape of Fields, which is how a Business Context is
// stored and read by everything outside Go. A change that a reader of an
// older document could misread gets a new name.
const Schema = "business_context/1"

var (
	// ErrInvalidContext is a Business Context that breaks one of its limits or
	// names a code outside its vocabularies.
	ErrInvalidContext = errors.New("invalid business context")
	// ErrStale is a save based on a version that is no longer the newest, as
	// when another User saved first.
	ErrStale = errors.New("the business context changed since it was read")
)

// Limits, in characters for text and in entries for lists.
const (
	MaxSummary   = 2000
	MaxStatement = 1000
	MaxNarrative = 4000
	MaxEntry     = 200
	MaxEntries   = 50
	MaxServices  = 25
)

// Fields are a Business Context as a User or the Drafter writes it. Every one
// is optional: blank text, an empty code and an empty list mean the Customer
// has not said.
type Fields struct {
	Profile    Profile    `json:"profile"`
	Geography  Geography  `json:"geography"`
	Operations Operations `json:"operations"`
	Footprint  Footprint  `json:"footprint"`
	Risk       Risk       `json:"risk"`
}

type Profile struct {
	// Summary is what the Customer does, for whom and how, up to MaxSummary.
	Summary string `json:"summary"`
	// Mission and Vision are up to MaxStatement each.
	Mission          string           `json:"mission"`
	Vision           string           `json:"vision"`
	Sectors          []Sector         `json:"sectors"`
	OrganizationType OrganizationType `json:"organization_type"`
	Employees        EmployeeRange    `json:"employees"`
	AnnualRevenue    RevenueRange     `json:"annual_revenue"`
}

// Geography holds ISO 3166-1 alpha-2 codes. Countries are where the Customer
// operates, its Headquarters among them.
type Geography struct {
	Headquarters string   `json:"headquarters"`
	Countries    []string `json:"countries"`
}

type Operations struct {
	CriticalServices []CriticalService `json:"critical_services"`
	DataCategories   []DataCategory    `json:"data_categories"`
	Regulations      []Regulation      `json:"regulations"`
	Environments     []Environment     `json:"environments"`
}

// CriticalService is a business service the Customer cannot afford to lose,
// and how much it tolerates losing it: its Impact and MaxDowntime. Assets are
// the names of the Assets that run it, as its CMDB Source writes them, which
// is how a Dossier names an Asset.
type CriticalService struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Impact      Impact   `json:"impact"`
	MaxDowntime Downtime `json:"max_downtime"`
	Assets      []string `json:"assets"`
}

// Footprint is what identifies the Customer outside its network, and what it
// depends on that is not an Asset: Technologies such as SaaS and platforms,
// and ThirdParties such as suppliers with access to its systems or data.
type Footprint struct {
	Domains      []string `json:"domains"`
	Brands       []string `json:"brands"`
	Technologies []string `json:"technologies"`
	ThirdParties []string `json:"third_parties"`
}

// Risk holds narratives up to MaxNarrative each. Constraints are what limits
// remediation, such as maintenance windows or systems that cannot be patched.
type Risk struct {
	Appetite      RiskAppetite `json:"appetite"`
	Concerns      []Concern    `json:"concerns"`
	PastIncidents string       `json:"past_incidents"`
	Constraints   string       `json:"constraints"`
	Notes         string       `json:"notes"`
}

// Context is a Customer's Business Context. The zero Context is one the
// Customer has not stated yet.
type Context struct {
	fields Fields
}

// New trims text, drops blank and repeated entries, canonicalizes domains
// and country codes, and adds the headquarters to the countries. It fails
// with ErrInvalidContext naming every problem Problems finds.
func New(f Fields) (Context, error) {
	normalized, problems := normalize(f)
	if len(problems) > 0 {
		return Context{}, fmt.Errorf("%w: %s", ErrInvalidContext, strings.Join(problems, "; "))
	}
	return Context{fields: normalized}, nil
}

// Problems are why New would reject f, each naming the field by its JSON
// path, such as "footprint.domains[2]".
func Problems(f Fields) []string {
	_, problems := normalize(f)
	return problems
}

// Fields are never nil slices, so an unstated list is an empty JSON array.
func (c Context) Fields() Fields { return c.fields.clone() }

var keyFields = []string{
	"profile.summary",
	"profile.sectors",
	"profile.employees",
	"profile.annual_revenue",
	"geography.countries",
	"operations.critical_services",
	"operations.data_categories",
	"footprint.domains",
	"footprint.technologies",
	"risk.appetite",
}

// KeyFields are the paths of what the Agents need most from a Business
// Context.
func KeyFields() []string { return slices.Clone(keyFields) }

// Gaps are the KeyFields the Customer has not stated, so that a reader never
// mistakes one for an answer.
func (c Context) Gaps() []string {
	f := c.fields
	stated := map[string]bool{
		"profile.summary":              f.Profile.Summary != "",
		"profile.sectors":              len(f.Profile.Sectors) > 0,
		"profile.employees":            f.Profile.Employees != "",
		"profile.annual_revenue":       f.Profile.AnnualRevenue != "",
		"geography.countries":          len(f.Geography.Countries) > 0,
		"operations.critical_services": len(f.Operations.CriticalServices) > 0,
		"operations.data_categories":   len(f.Operations.DataCategories) > 0,
		"footprint.domains":            len(f.Footprint.Domains) > 0,
		"footprint.technologies":       len(f.Footprint.Technologies) > 0,
		"risk.appetite":                f.Risk.Appetite != "",
	}
	gaps := []string{}
	for _, path := range keyFields {
		if !stated[path] {
			gaps = append(gaps, path)
		}
	}
	return gaps
}

func (f Fields) clone() Fields {
	services := make([]CriticalService, len(f.Operations.CriticalServices))
	for i, s := range f.Operations.CriticalServices {
		services[i] = CriticalService{Name: s.Name, Description: s.Description, Impact: s.Impact, MaxDowntime: s.MaxDowntime, Assets: cloned(s.Assets)}
	}
	return Fields{
		Profile: Profile{
			Summary: f.Profile.Summary, Mission: f.Profile.Mission, Vision: f.Profile.Vision,
			Sectors: cloned(f.Profile.Sectors), OrganizationType: f.Profile.OrganizationType,
			Employees: f.Profile.Employees, AnnualRevenue: f.Profile.AnnualRevenue,
		},
		Geography: Geography{Headquarters: f.Geography.Headquarters, Countries: cloned(f.Geography.Countries)},
		Operations: Operations{
			CriticalServices: services, DataCategories: cloned(f.Operations.DataCategories),
			Regulations: cloned(f.Operations.Regulations), Environments: cloned(f.Operations.Environments),
		},
		Footprint: Footprint{
			Domains: cloned(f.Footprint.Domains), Brands: cloned(f.Footprint.Brands),
			Technologies: cloned(f.Footprint.Technologies), ThirdParties: cloned(f.Footprint.ThirdParties),
		},
		Risk: Risk{
			Appetite: f.Risk.Appetite, Concerns: cloned(f.Risk.Concerns),
			PastIncidents: f.Risk.PastIncidents, Constraints: f.Risk.Constraints, Notes: f.Risk.Notes,
		},
	}
}

func cloned[T any](s []T) []T { return append([]T{}, s...) }

type checker struct {
	problems []string
}

func (c *checker) fail(path, format string, args ...any) {
	c.problems = append(c.problems, path+" "+fmt.Sprintf(format, args...))
}

func normalize(f Fields) (Fields, []string) {
	c := &checker{}
	hq := c.country("geography.headquarters", f.Geography.Headquarters)
	countries := c.entries(f.Geography.Countries, "geography.countries", c.canonicalCountry)
	if hq != "" && !slices.Contains(countries, hq) {
		countries = append([]string{hq}, countries...)
	}
	return Fields{
		Profile: Profile{
			Summary:          c.text("profile.summary", f.Profile.Summary, MaxSummary),
			Mission:          c.text("profile.mission", f.Profile.Mission, MaxStatement),
			Vision:           c.text("profile.vision", f.Profile.Vision, MaxStatement),
			Sectors:          codes(c, "profile.sectors", f.Profile.Sectors, sectors),
			OrganizationType: code(c, "profile.organization_type", f.Profile.OrganizationType, organizationTypes),
			Employees:        code(c, "profile.employees", f.Profile.Employees, employeeRanges),
			AnnualRevenue:    code(c, "profile.annual_revenue", f.Profile.AnnualRevenue, revenueRanges),
		},
		Geography: Geography{Headquarters: hq, Countries: c.limit("geography.countries", countries, MaxEntries)},
		Operations: Operations{
			CriticalServices: c.services(f.Operations.CriticalServices),
			DataCategories:   codes(c, "operations.data_categories", f.Operations.DataCategories, dataCategories),
			Regulations:      codes(c, "operations.regulations", f.Operations.Regulations, regulations),
			Environments:     codes(c, "operations.environments", f.Operations.Environments, environments),
		},
		Footprint: Footprint{
			Domains:      c.list("footprint.domains", f.Footprint.Domains, c.canonicalDomain),
			Brands:       c.list("footprint.brands", f.Footprint.Brands, c.plain),
			Technologies: c.list("footprint.technologies", f.Footprint.Technologies, c.plain),
			ThirdParties: c.list("footprint.third_parties", f.Footprint.ThirdParties, c.plain),
		},
		Risk: Risk{
			Appetite:      code(c, "risk.appetite", f.Risk.Appetite, riskAppetites),
			Concerns:      codes(c, "risk.concerns", f.Risk.Concerns, concerns),
			PastIncidents: c.text("risk.past_incidents", f.Risk.PastIncidents, MaxNarrative),
			Constraints:   c.text("risk.constraints", f.Risk.Constraints, MaxNarrative),
			Notes:         c.text("risk.notes", f.Risk.Notes, MaxNarrative),
		},
	}, c.problems
}

func (c *checker) text(path, s string, limit int) string {
	s = strings.TrimSpace(s)
	if n := utf8.RuneCountInString(s); n > limit {
		c.fail(path, "has %d characters, more than %d", n, limit)
	}
	return s
}

func code[T ~string](c *checker, path string, value T, v vocabulary[T]) T {
	if value != "" && !v.has(value) {
		c.fail(path, "is %q, which is none of its codes", value)
	}
	return value
}

func codes[T ~string](c *checker, path string, values []T, v vocabulary[T]) []T {
	out := []T{}
	for i, value := range values {
		switch {
		case !v.has(value):
			c.fail(fmt.Sprintf("%s[%d]", path, i), "is %q, which is none of its codes", value)
		case !slices.Contains(out, value):
			out = append(out, value)
		}
	}
	return out
}

func (c *checker) list(path string, values []string, canonical func(path, entry string) (string, bool)) []string {
	return c.limit(path, c.entries(values, path, canonical), MaxEntries)
}

// entries trims each entry and drops blank ones and those repeated regardless
// of case. canonical returns the entry's canonical form, or false when it is
// not a valid one.
func (c *checker) entries(values []string, path string, canonical func(path, entry string) (string, bool)) []string {
	out := []string{}
	seen := map[string]bool{}
	for i, value := range values {
		entry, ok := canonical(fmt.Sprintf("%s[%d]", path, i), strings.TrimSpace(value))
		key := strings.ToLower(entry)
		if !ok || entry == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, entry)
	}
	return out
}

func (c *checker) limit(path string, values []string, limit int) []string {
	if len(values) > limit {
		c.fail(path, "has %d entries, more than %d", len(values), limit)
	}
	return values
}

func (c *checker) plain(path, entry string) (string, bool) {
	if n := utf8.RuneCountInString(entry); n > MaxEntry {
		c.fail(path, "has %d characters, more than %d", n, MaxEntry)
		return "", false
	}
	return entry, true
}

var domainName = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// canonicalDomain keeps the host of a URL, lowercased and without "www.",
// since a Customer's domain is what lookalikes and leaks are matched to.
func (c *checker) canonicalDomain(path, entry string) (string, bool) {
	d := strings.ToLower(entry)
	for _, scheme := range []string{"https://", "http://"} {
		d = strings.TrimPrefix(d, scheme)
	}
	d, _, _ = strings.Cut(d, "/")
	d = strings.TrimPrefix(strings.TrimSuffix(d, "."), "www.")
	if d == "" {
		return "", true
	}
	if len(d) > 253 || !domainName.MatchString(d) {
		c.fail(path, "is %q, which is not a domain name such as example.com", entry)
		return "", false
	}
	return d, true
}

func (c *checker) canonicalCountry(path, entry string) (string, bool) {
	iso := strings.ToUpper(entry)
	if iso != "" && !slices.Contains(countries, iso) {
		c.fail(path, "is %q, which is not an ISO 3166-1 alpha-2 country code", entry)
		return "", false
	}
	return iso, true
}

func (c *checker) country(path, entry string) string {
	iso, _ := c.canonicalCountry(path, strings.TrimSpace(entry))
	return iso
}

func (s CriticalService) empty() bool {
	return s.Name == "" && s.Description == "" && s.Impact == "" && s.MaxDowntime == "" && len(s.Assets) == 0
}

func (c *checker) services(list []CriticalService) []CriticalService {
	out := []CriticalService{}
	names := map[string]bool{}
	for i, s := range list {
		path := fmt.Sprintf("operations.critical_services[%d]", i)
		service := CriticalService{
			Name:        c.text(path+".name", s.Name, MaxEntry),
			Description: c.text(path+".description", s.Description, MaxStatement),
			Impact:      code(c, path+".impact", s.Impact, impacts),
			MaxDowntime: code(c, path+".max_downtime", s.MaxDowntime, downtimes),
			Assets:      c.list(path+".assets", s.Assets, c.plain),
		}
		key := strings.ToLower(service.Name)
		switch {
		case service.empty():
			continue
		case service.Name == "":
			c.fail(path+".name", "is blank")
		case names[key]:
			c.fail(path+".name", "repeats %q", service.Name)
		}
		names[key] = true
		out = append(out, service)
	}
	if len(out) > MaxServices {
		c.fail("operations.critical_services", "has %d entries, more than %d", len(out), MaxServices)
	}
	return out
}
