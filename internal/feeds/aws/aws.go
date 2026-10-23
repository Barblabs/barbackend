// Package aws pulls the AWS Security Bulletins RSS feed.
package aws

import (
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"barbackend/internal/feeds"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

const defaultURL = "https://aws.amazon.com/security/security-bulletins/rss/feed/"

var dateLayouts = []string{time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822}

// Adapter fetches the AWS Security Bulletins RSS feed.
type Adapter struct {
	Client *http.Client
	URL    string
}

// New returns an Adapter, defaulting the client and URL when they are empty.
func New(client *http.Client, url string) *Adapter {
	if client == nil {
		client = http.DefaultClient
	}
	if strings.TrimSpace(url) == "" {
		url = defaultURL
	}
	return &Adapter{Client: client, URL: url}
}

// Pull fetches the feed and emits one Report per bulletin.
func (a *Adapter) Pull(ctx context.Context, emit feeds.Emit) error {
	f, err := a.fetch(ctx)
	if err != nil {
		return err
	}
	for _, item := range f.Channel.Items {
		r, ok, err := report(item)
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

func (a *Adapter) fetch(ctx context.Context) (rss, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return rss{}, fmt.Errorf("aws: %w", err)
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return rss{}, fmt.Errorf("aws: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return rss{}, fmt.Errorf("aws: %s: %s", a.URL, resp.Status)
	}
	var f rss
	if err := xml.NewDecoder(resp.Body).Decode(&f); err != nil {
		return rss{}, fmt.Errorf("aws: decode feed: %w", err)
	}
	return f, nil
}

func report(item item) (*stix2.Report, bool, error) {
	guid := strings.TrimSpace(item.GUID)
	if guid == "" {
		log.Printf("aws: skipping %q: no guid", item.Title)
		return nil, false, nil
	}
	published, err := parseDate(item.PubDate)
	if err != nil {
		return nil, false, fmt.Errorf("aws: %s: published %q: %w", guid, item.PubDate, err)
	}
	refs := []*stix2.ExternalReference{
		{Name: "aws", URL: item.Link},
		{Name: "guid", ExternalID: guid},
	}
	r, err := stix2.NewReport(item.Title, &stix2.Timestamp{Time: published}, []stix2.Identifier{stixext.BarbattackID},
		stix2.OptionCreatedBy(stixext.BarbattackID),
		stix2.OptionDescription(item.Description),
		stix2.OptionExternalReferences(refs),
		stix2.OptionObjectMarking([]stix2.Identifier{stixext.TLPClear}),
	)
	if err != nil {
		return nil, false, fmt.Errorf("aws: %s: %w", guid, err)
	}
	r.ID = stixext.ID(stix2.TypeReport, guid)
	r.Objects = []stix2.Identifier{}
	return r, true, nil
}

func parseDate(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("want an RFC 1123 or RFC 822 date")
}

type rss struct {
	Channel channel `xml:"channel"`
}

type channel struct {
	Items []item `xml:"item"`
}

type item struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	GUID        string `xml:"guid"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
}
