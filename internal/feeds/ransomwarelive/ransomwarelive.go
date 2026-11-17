// Package ransomwarelive pulls the leak-site posts that ransomware.live
// relays: each one a victim, with its sectors, country and domain, and the
// News Item claiming the attack on it, read without a model (ADR 0025).
package ransomwarelive

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"barbackend/internal/feeds"
	"barbackend/internal/feeds/httpx"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

const (
	feed       = "ransomwarelive"
	defaultURL = "https://api.ransomware.live/v2/recentvictims"
)

// sectors maps ransomware.live's activities, lowercased, to codes of
// business.Sectors(). An activity it does not hold, or one that names no
// industry such as "Not Found", "Other", "Consumer Services" or "Business
// Services", maps to none: a sector is left out, never guessed (ADR 0025).
var sectors = map[string][]string{
	"agriculture and food production": {"agriculture", "food-beverage"},
	"construction":                    {"construction"},
	"education":                       {"education"},
	"energy & utilities":              {"energy", "utilities"},
	"financial services":              {"financial-services"},
	"government & defense":            {"government", "defense"},
	"healthcare":                      {"healthcare"},
	"hospitality":                     {"hospitality-leisure"},
	"hospitality and tourism":         {"hospitality-leisure"},
	"insurance":                       {"insurance"},
	"legal":                           {"legal"},
	"manufacturing":                   {"manufacturing"},
	"media & internet":                {"media"},
	"pharmaceutical":                  {"pharmaceuticals"},
	"professional services":           {"professional-services"},
	"public sector":                   {"government"},
	"retail & e-commerce":             {"retail", "e-commerce"},
	"technology":                      {"technology"},
	"telecommunication":               {"telecommunications"},
	"transportation":                  {"transportation"},
	"transportation/logistics":        {"transportation", "logistics"},
}

// domainName is a domain as a Business Context writes one (ADR 0017).
var domainName = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Adapter fetches ransomware.live's most recent victims.
type Adapter struct {
	httpx.Endpoint
}

// New returns an Adapter, defaulting the client and URL when they are empty.
func New(client *http.Client, url string) *Adapter {
	return &Adapter{Endpoint: httpx.NewEndpoint(client, url, defaultURL)}
}

// Pull fetches the recent victims and emits, for each post, the victim's
// Identity and then the Report of the post.
func (a *Adapter) Pull(ctx context.Context, emit feeds.Emit) error {
	posts, err := a.fetch(ctx)
	if err != nil {
		return err
	}
	for _, p := range posts {
		objs, err := objects(p)
		if err != nil {
			return err
		}
		for _, o := range objs {
			if err := emit(o); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *Adapter) fetch(ctx context.Context) ([]post, error) {
	resp, err := a.Get(ctx, feed)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var posts []post
	if err := json.NewDecoder(resp.Body).Decode(&posts); err != nil {
		return nil, fmt.Errorf("%s: decode victims: %w", feed, err)
	}
	return posts, nil
}

// objects are p's victim and the Report of p, in that order, or none when p
// names no victim or has no readable date.
func objects(p post) ([]stix2.STIXObject, error) {
	name := strings.TrimSpace(p.Victim)
	if name == "" {
		log.Printf("%s: skipping %s: no victim", feed, p.URL)
		return nil, nil
	}
	key := cmp.Or(strings.TrimSpace(p.URL), name+"@"+strings.TrimSpace(p.Group))
	published, err := firstDate(p.AttackDate, p.Discovered)
	if err != nil {
		log.Printf("%s: skipping %s: attackdate %q, discovered %q: %v", feed, key, p.AttackDate, p.Discovered, err)
		return nil, nil
	}
	v, err := victim(p, name, key)
	if err != nil {
		return nil, fmt.Errorf("%s: %s: victim: %w", feed, key, err)
	}
	r, err := report(p, name, key, published, v.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %w", feed, key, err)
	}
	return []stix2.STIXObject{v, r}, nil
}

func victim(p post, name, key string) (*stix2.Identity, error) {
	domain := canonicalDomain(p.Domain)
	opts := []stix2.STIXOption{
		stix2.OptionClass(stix2.IdentityClassOrganization),
		stix2.OptionCreatedBy(stixext.BarbattackID),
		stix2.OptionObjectMarking([]stix2.Identifier{stixext.TLPClear}),
		stix2.OptionExtension(string(stixext.VictimDefinitionID), stixext.NewVictim(stixext.Victim{
			Countries: countries(p.Country), Domain: domain,
		})),
	}
	if s := sectorsOf(p.Activity); len(s) > 0 {
		opts = append(opts, stix2.OptionSectors(s))
	}
	i, err := stix2.NewIdentity(name, opts...)
	if err != nil {
		return nil, err
	}
	i.ID = stixext.VictimID(domain, feed, key)
	return i, nil
}

func report(p post, name, key string, published time.Time, victim stix2.Identifier) (*stix2.Report, error) {
	description := strings.TrimSpace(p.Description)
	objects := []stix2.Identifier{victim}
	for _, cve := range stixext.CVEIDs(description) {
		objects = append(objects, stixext.VulnerabilityID(cve))
	}
	link := webURL(p.URL)
	var refs []*stix2.ExternalReference
	if link != "" {
		refs = append(refs, &stix2.ExternalReference{Name: feed, URL: link})
	}
	r, err := stix2.NewReport(name, &stix2.Timestamp{Time: published}, objects,
		stix2.OptionCreatedBy(stixext.BarbattackID),
		stix2.OptionDescription(description),
		stix2.OptionExternalReferences(refs),
		stix2.OptionObjectMarking([]stix2.Identifier{stixext.TLPClear}),
		stix2.OptionExtension(string(stixext.NewsDefinitionID), stixext.NewNews(stixext.News{
			Feed: feed, Kind: stixext.NewsLeakPost, Attacker: strings.TrimSpace(p.Group), Link: link,
		})),
	)
	if err != nil {
		return nil, err
	}
	r.ID = stixext.ID(stix2.TypeReport, feed+":"+key)
	return r, nil
}

// firstDate is the first of dates that is an RFC 3339 timestamp, in UTC.
func firstDate(dates ...string) (time.Time, error) {
	for _, s := range dates {
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(s)); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("want an RFC 3339 date")
}

// canonicalDomain is raw as a Business Context writes a domain: lowercased,
// without scheme, path, port or a leading "www.". It is "" when raw is not a
// domain, as when ransomware.live writes the victim's name, or a masked
// domain such as "i****.c**", in its place.
func canonicalDomain(raw string) string {
	d := strings.ToLower(strings.TrimSpace(raw))
	if _, host, ok := strings.Cut(d, "://"); ok {
		d = host
	}
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	d, _, _ = strings.Cut(d, ":")
	d = strings.TrimPrefix(strings.TrimSuffix(d, "."), "www.")
	if len(d) > 253 || !domainName.MatchString(d) {
		return ""
	}
	return d
}

func sectorsOf(activity string) []string {
	return slices.Clone(sectors[strings.ToLower(strings.TrimSpace(activity))])
}

// countries is country as ISO 3166-1 alpha-2, when it is two letters.
func countries(country string) []string {
	c := strings.ToUpper(strings.TrimSpace(country))
	if len(c) != 2 || c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z' {
		return nil
	}
	return []string{c}
}

// webURL is s when it is an absolute http or https URL, else "": a link is
// shown to people, and a Feed's text is untrusted.
func webURL(s string) string {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return s
}

// post is one victim as ransomware.live's v2 API lists it.
type post struct {
	Activity    string `json:"activity"`
	AttackDate  string `json:"attackdate"`
	Country     string `json:"country"`
	Description string `json:"description"`
	Discovered  string `json:"discovered"`
	Domain      string `json:"domain"`
	Group       string `json:"group"`
	URL         string `json:"url"`
	Victim      string `json:"victim"`
}
