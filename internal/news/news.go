// Package news holds the News Items that Feeds publish about attacks and
// Vulnerabilities, what the Reader states of them, and the rules that give
// each its Relevance to one Customer (ADR 0025). It does no I/O, and no model
// decides anything in it.
package news

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"barbackend/internal/business"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

// ErrNotNews is a STIX report without the news/1 extension.
var ErrNotNews = errors.New("report is not a news item")

// Item is one News Item: an article or a leak-site post that a Feed
// published. It belongs to no Customer, and its text is untrusted data.
type Item struct {
	ID        string
	Feed      string
	Kind      string
	Title     string
	Text      string
	Link      string
	Language  string
	Published time.Time
	// CVEs are the CVE IDs its text names.
	CVEs []string
	// Attacker is who claims a leak post, as the Feed names it.
	Attacker string
	// Victims are the victims a structured Feed names, with their sectors,
	// countries and domain. A text Feed names none: the Reader states them.
	Victims []Victim
}

// Victim is an organization a Reported Attack hit.
type Victim struct {
	Name      string            `json:"name"`
	Domain    string            `json:"domain,omitempty"`
	Sectors   []business.Sector `json:"sectors"`
	Countries []string          `json:"countries"`
}

// IsLeakPost reports whether i is an attacker's own claim on a leak site.
func (i Item) IsLeakPost() bool { return i.Kind == stixext.NewsLeakPost }

// ItemFrom reads the News Item of r, with the victims it refers to among
// identities.
func ItemFrom(r *stix2.Report, identities []*stix2.Identity) (Item, error) {
	ext, ok := stixext.NewsOf(r)
	if !ok {
		return Item{}, fmt.Errorf("%s: %w", r.ID, ErrNotNews)
	}
	item := Item{
		ID:       string(r.ID),
		Feed:     ext.Feed,
		Kind:     ext.Kind,
		Title:    strings.TrimSpace(r.Name),
		Text:     strings.TrimSpace(r.Description),
		Link:     ext.Link,
		Language: ext.Language,
		Attacker: strings.TrimSpace(ext.Attacker),
		CVEs:     CVEsOf(r),
	}
	if r.Published != nil {
		item.Published = r.Published.UTC()
	}
	for _, identity := range identities {
		if slices.Contains(r.Objects, identity.ID) {
			item.Victims = append(item.Victims, victimFrom(identity))
		}
	}
	return item, nil
}

// CVEsOf is the CVE IDs r names: those its text mentions whose Vulnerability
// it refers to, since a Vulnerability's STIX id cannot be read back.
func CVEsOf(r *stix2.Report) []string {
	var out []string
	for _, cve := range stixext.CVEIDs(r.Name + " " + r.Description) {
		if slices.Contains(r.Objects, stixext.VulnerabilityID(cve)) && !slices.Contains(out, cve) {
			out = append(out, cve)
		}
	}
	return out
}

func victimFrom(identity *stix2.Identity) Victim {
	v := Victim{Name: strings.TrimSpace(identity.Name), Sectors: []business.Sector{}, Countries: []string{}}
	for _, s := range identity.Sectors {
		if sector := business.Sector(s); slices.Contains(business.Sectors(), sector) {
			v.Sectors = append(v.Sectors, sector)
		}
	}
	if ext, ok := stixext.VictimOf(identity); ok {
		v.Domain = ext.Domain
		for _, c := range ext.Countries {
			if business.IsCountry(c) {
				v.Countries = append(v.Countries, c)
			}
		}
	}
	return v
}
