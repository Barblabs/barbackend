package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"barbackend/internal/advisories"
	"barbackend/internal/feeds/attack"
	"barbackend/internal/feeds/aws"
	"barbackend/internal/feeds/epss"
	"barbackend/internal/feeds/kev"
	"barbackend/internal/feeds/nvd"
	"barbackend/internal/feeds/ransomwarelive"
	"barbackend/internal/feeds/rss"
	"barbackend/internal/findings"
	"barbackend/internal/ingest"
	"barbackend/internal/newsitems"
	"barbackend/internal/techniques"
	"github.com/TcM1911/stix2"
)

const feedSynopsis = "pull [--feed <name>]"

const (
	kevInterval    = time.Hour
	nvdInterval    = 2 * time.Hour
	attackInterval = 12 * time.Hour
	awsInterval    = 6 * time.Hour
	epssInterval   = 24 * time.Hour
	// News Feeds keep a short window, so they are pulled before it fills
	// (ADR 0025): hourly in English and for leak sites, every two hours for
	// the slower Spanish ones.
	newsInterval        = time.Hour
	spanishNewsInterval = 2 * time.Hour
	// kevMaxAge is how old the KEV catalog may be before a Score marks it
	// stale (ADR 0009): two missed pulls.
	kevMaxAge = 2 * kevInterval
)

func feed(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "pull" {
		return errors.New("usage: barbackend feed " + feedSynopsis)
	}
	flags := flag.NewFlagSet("feed pull", flag.ExitOnError)
	name := flags.String("feed", "", "`name` of the Feed to pull; every registered Feed when empty")
	_ = flags.Parse(args[1:])

	return pullFeeds(ctx, os.Stdout, registeredFeeds(), *name)
}

func pullFeeds(ctx context.Context, out io.Writer, feeds []ingest.Feed, name string) error {
	svc, err := ingest.New(feeds...)
	if err != nil {
		return err
	}
	if name != "" {
		count, err := svc.Pull(ctx, name)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(out, "%s: %d\n", name, count)
		return nil
	}
	var failed bool
	for _, r := range svc.PullAll(ctx) {
		if r.Err != nil {
			_, _ = fmt.Fprintf(out, "%s: failed: %v\n", r.Feed, r.Err)
			failed = true
			continue
		}
		_, _ = fmt.Fprintf(out, "%s: %d\n", r.Feed, r.Count)
	}
	if failed {
		return errors.New("one or more feeds failed")
	}
	return nil
}

// handledBy has NVD, KEV and EPSS hand what they pull to the Findings
// (ADR 0020), AWS hand its bulletins to the Advisories (ADR 0022) and ATT&CK
// hand its catalog to the Techniques (ADR 0023). feed pull runs without them,
// so it needs no database.
func handledBy(f *findings.Service, a *advisories.Service, t *techniques.Service, n *newsitems.Service, feeds []ingest.Feed) []ingest.Feed {
	handlers := map[string]func(context.Context, []stix2.STIXObject) error{
		"nvd":    f.HandleNVD,
		"kev":    f.HandleKEV,
		"epss":   f.HandleEPSS,
		"aws":    a.HandleAWS,
		"attack": t.HandleATTACK,
	}
	for _, name := range newsFeeds() {
		handlers[name] = n.HandleNews
	}
	out := make([]ingest.Feed, len(feeds))
	for i, feed := range feeds {
		feed.Handle = handlers[feed.Name]
		out[i] = feed
	}
	return out
}

// newsFeeds are the names of the Feeds of News Items, ransomwarelive's
// whether or not it is enabled.
func newsFeeds() []string {
	names := []string{ransomwareLive}
	for _, c := range rss.Defaults() {
		names = append(names, c.Name)
	}
	return names
}

const ransomwareLive = "ransomwarelive"

// ransomwareLiveEnabled reports whether RANSOMWARELIVE_ENABLED is true.
// Ransomware.live's terms forbid commercial use of its data without the
// owner's written approval, so it is never polled unless an operator who has
// that approval says so.
func ransomwareLiveEnabled() bool {
	enabled, _ := strconv.ParseBool(strings.TrimSpace(os.Getenv("RANSOMWARELIVE_ENABLED")))
	return enabled
}

func newsFeedsRegistered() []ingest.Feed {
	var out []ingest.Feed
	for _, c := range rss.Defaults() {
		interval := newsInterval
		if c.Language == "es" {
			interval = spanishNewsInterval
		}
		out = append(out, ingest.Feed{Name: c.Name, Interval: interval, Pull: rss.New(nil, c).Pull})
	}
	if ransomwareLiveEnabled() {
		out = append(out, ingest.Feed{Name: ransomwareLive, Interval: newsInterval, Pull: ransomwarelive.New(nil, "").Pull})
	}
	return out
}

func registeredFeeds() []ingest.Feed {
	return append([]ingest.Feed{
		{
			Name:     "kev",
			Interval: kevInterval,
			Pull:     kev.New(nil, "").Pull,
		},
		{
			Name:     "nvd",
			Interval: nvdInterval,
			Pull:     nvd.New(nil, "", os.Getenv("NVD_API_KEY")).Pull,
		},
		{
			Name:     "attack",
			Interval: attackInterval,
			Pull:     attack.New(nil, "").Pull,
		},
		{
			Name:     "aws",
			Interval: awsInterval,
			Pull:     aws.New(nil, "").Pull,
		},
		{
			Name:     "epss",
			Interval: epssInterval,
			Pull:     epss.New(nil, "").Pull,
		},
	}, newsFeedsRegistered()...)
}
