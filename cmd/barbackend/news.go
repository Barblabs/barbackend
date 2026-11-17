package main

import (
	"context"
	"log"
	"time"
)

const (
	// newsRunDelay leaves the Feeds' first pulls time to store News Items before
	// the Reader's first run (ADR 0025).
	newsRunDelay = 20 * time.Minute
	// newsRunInterval is how often the Reader reads what the Feeds stored and
	// each Customer whose last News Digest is a day old gets its next one.
	newsRunInterval = time.Hour
)

// newsHourly runs the Reader and then the Editor after delay, then every
// interval, until ctx is done. A failed run is logged, and the next one tries
// again; a Reader that fails does not keep the Editor from digesting what is
// ready.
func newsHourly(ctx context.Context, read, digest func(context.Context) error, delay, interval time.Duration) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := read(ctx); err != nil && ctx.Err() == nil {
			log.Printf("reader: run failed: %v", err)
		}
		if err := digest(ctx); err != nil && ctx.Err() == nil {
			log.Printf("editor: run failed: %v", err)
		}
		timer.Reset(interval)
	}
}
