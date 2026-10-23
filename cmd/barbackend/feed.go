package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"barbackend/internal/feeds/attack"
	"barbackend/internal/feeds/aws"
	"barbackend/internal/feeds/epss"
	"barbackend/internal/feeds/kev"
	"barbackend/internal/feeds/nvd"
	"barbackend/internal/ingest"
)

const feedSynopsis = "pull [--feed <name>]"

const (
	kevInterval    = time.Hour
	nvdInterval    = 2 * time.Hour
	attackInterval = 12 * time.Hour
	awsInterval    = 6 * time.Hour
	epssInterval   = 24 * time.Hour
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

func registeredFeeds() []ingest.Feed {
	return []ingest.Feed{
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
	}
}
