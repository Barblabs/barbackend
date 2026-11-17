// Package rss pulls a news site's RSS or Atom feed: every text Feed of ADR 0025.
package rss

import (
	"cmp"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"barbackend/internal/feeds"
	"barbackend/internal/feeds/httpx"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

const (
	atomNS    = "http://www.w3.org/2005/Atom"
	contentNS = "http://purl.org/rss/1.0/modules/content/"
	dcNS      = "http://purl.org/dc/elements/1.1/"
)

// dateLayouts are RFC 1123 and RFC 822 dates as feeds write them, with a day
// of one or two digits, with or without the weekday and seconds, and RFC 3339.
var dateLayouts = []string{
	"Mon, 2 Jan 2006 15:04:05 -0700",
	"Mon, 2 Jan 2006 15:04:05 MST",
	"Mon, 2 Jan 2006 15:04 -0700",
	"Mon, 2 Jan 2006 15:04 MST",
	"2 Jan 2006 15:04:05 -0700",
	"2 Jan 2006 15:04:05 MST",
	"Mon, 2 Jan 06 15:04:05 -0700",
	"Mon, 2 Jan 06 15:04:05 MST",
	time.RFC822Z,
	time.RFC822,
	time.RFC3339,
}

// Config is one text Feed.
type Config struct {
	// Name is the Feed as registered: lowercase, no spaces.
	Name string
	URL  string
	// Language is BCP 47, such as en or es.
	Language string
}

// Defaults are the text Feeds of ADR 0025. BleepingComputer is left out: its
// feed answers Go's HTTP client with a Cloudflare challenge (403).
func Defaults() []Config {
	return []Config{
		{Name: "therecord", URL: "https://therecord.media/feed", Language: "en"},
		{Name: "thehackernews", URL: "https://feeds.feedburner.com/TheHackersNews", Language: "en"},
		{Name: "securityweek", URL: "https://www.securityweek.com/feed/", Language: "en"},
		{Name: "darkreading", URL: "https://www.darkreading.com/rss.xml", Language: "en"},
		{Name: "databreaches", URL: "https://databreaches.net/feed/", Language: "en"},
		{Name: "welivesecurity", URL: "https://www.welivesecurity.com/es/rss/feed/", Language: "es"},
		{Name: "unaaldia", URL: "https://unaaldia.hispasec.com/feed/", Language: "es"},
	}
}

// Adapter fetches one text Feed.
type Adapter struct {
	httpx.Endpoint
	name, language string
}

// New returns an Adapter for c, defaulting the client when it is nil.
func New(client *http.Client, c Config) *Adapter {
	return &Adapter{Endpoint: httpx.NewEndpoint(client, c.URL, ""), name: c.Name, language: c.Language}
}

// Pull fetches the feed and emits one Report per item.
func (a *Adapter) Pull(ctx context.Context, emit feeds.Emit) error {
	items, err := a.fetch(ctx)
	if err != nil {
		return err
	}
	for _, it := range items {
		r, ok, err := a.report(it)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if err := emit(r); err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) fetch(ctx context.Context) ([]item, error) {
	resp, err := a.Get(ctx, a.name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	items, err := parse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", a.name, err)
	}
	return items, nil
}

func (a *Adapter) report(it item) (*stix2.Report, bool, error) {
	link := webURL(it.link)
	key := cmp.Or(it.guid, link)
	if key == "" {
		log.Printf("%s: skipping %q: no guid or link", a.name, it.title)
		return nil, false, nil
	}
	title := plainText(it.title)
	if title == "" {
		log.Printf("%s: skipping %s: no title", a.name, key)
		return nil, false, nil
	}
	published, err := parseDate(it.date)
	if err != nil {
		log.Printf("%s: skipping %s: published %q: %v", a.name, key, it.date, err)
		return nil, false, nil
	}
	description := plainText(it.summary)
	objects := make([]stix2.Identifier, 0, 1)
	for _, cve := range stixext.CVEIDs(title + " " + description) {
		objects = append(objects, stixext.VulnerabilityID(cve))
	}
	if len(objects) == 0 {
		// STIX needs one ref; the creator's says nothing about the item (ADR 0010).
		objects = append(objects, stixext.BarbattackID)
	}
	refs := make([]*stix2.ExternalReference, 0, 2)
	if link != "" {
		refs = append(refs, &stix2.ExternalReference{Name: a.name, URL: link})
	}
	if it.guid != "" {
		refs = append(refs, &stix2.ExternalReference{Name: "guid", ExternalID: it.guid})
	}
	r, err := stix2.NewReport(title, &stix2.Timestamp{Time: published}, objects,
		stix2.OptionCreatedBy(stixext.BarbattackID),
		stix2.OptionDescription(description),
		stix2.OptionExternalReferences(refs),
		stix2.OptionObjectMarking([]stix2.Identifier{stixext.TLPClear}),
		stix2.OptionExtension(string(stixext.NewsDefinitionID), stixext.NewNews(stixext.News{
			Feed: a.name, Kind: stixext.NewsArticle, Language: a.language, Link: link,
		})),
	)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %s: %w", a.name, key, err)
	}
	r.ID = stixext.ID(stix2.TypeReport, a.name+":"+key)
	return r, true, nil
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

func parseDate(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("no date")
	}
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("want an RFC 1123, RFC 822 or RFC 3339 date")
}

// item is what the adapter reads of an RSS item or an Atom entry, as the
// feed writes it.
type item struct {
	guid, link, title, summary, date string
}

// document is an RSS 2.0 feed, whose items are in its channel, or an Atom
// feed, whose entries are at its root.
type document struct {
	XMLName xml.Name
	Items   []entry `xml:"channel>item"`
	Entries []entry `xml:"entry"`
}

// entry is an RSS item or an Atom entry. Its children are read by namespace
// and name, so an extension such as media:description or atom:link never
// stands for the item's own.
type entry struct {
	Children []element `xml:",any"`
}

type element struct {
	XMLName xml.Name
	Rel     string `xml:"rel,attr"`
	Href    string `xml:"href,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
	Inner   string `xml:",innerxml"`
}

func parse(r io.Reader) ([]item, error) {
	dec := xml.NewDecoder(r)
	dec.Entity = xml.HTMLEntity
	var doc document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode feed: %w", err)
	}
	var items []item
	switch doc.XMLName {
	case xml.Name{Local: "rss"}:
		for _, e := range doc.Items {
			items = append(items, e.rss())
		}
	case xml.Name{Space: atomNS, Local: "feed"}:
		for _, e := range doc.Entries {
			items = append(items, e.atom())
		}
	default:
		return nil, fmt.Errorf("want an RSS or Atom feed, got <%s>", doc.XMLName.Local)
	}
	return items, nil
}

func (e entry) rss() item {
	return item{
		guid:    e.text("", "guid"),
		link:    e.text("", "link"),
		title:   e.text("", "title"),
		summary: cmp.Or(e.text("", "description"), e.text(contentNS, "encoded")),
		date:    cmp.Or(e.text("", "pubDate"), e.text(dcNS, "date")),
	}
}

func (e entry) atom() item {
	return item{
		guid:    e.text(atomNS, "id"),
		link:    e.alternate(),
		title:   e.markup("title"),
		summary: cmp.Or(strings.TrimSpace(e.markup("summary")), e.markup("content")),
		date:    cmp.Or(e.text(atomNS, "published"), e.text(atomNS, "updated")),
	}
}

func (e entry) find(space, local string) element {
	for _, c := range e.Children {
		if c.XMLName.Space == space && c.XMLName.Local == local {
			return c
		}
	}
	return element{}
}

func (e entry) text(space, local string) string {
	return strings.TrimSpace(e.find(space, local).Text)
}

// markup is an Atom text construct as HTML: one of type xhtml holds its
// markup as child elements, the others as text.
func (e entry) markup(local string) string {
	c := e.find(atomNS, local)
	if c.Type == "xhtml" {
		return c.Inner
	}
	return c.Text
}

// alternate is the href of an Atom entry's alternate link: its page.
func (e entry) alternate() string {
	for _, c := range e.Children {
		if c.XMLName == (xml.Name{Space: atomNS, Local: "link"}) && (c.Rel == "" || c.Rel == "alternate") {
			return strings.TrimSpace(c.Href)
		}
	}
	return ""
}
