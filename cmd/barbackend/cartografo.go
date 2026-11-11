package main

import (
	"context"
	"log"
	"time"

	"barbackend/internal/agents"
)

const (
	// labelingDelay leaves the Feeds' first pulls, ATT&CK's among them, time
	// to finish before the Cartógrafo's first run (ADR 0024).
	labelingDelay = 15 * time.Minute
	// labelingInterval is how often the Cartógrafo runs: a label adds to what
	// a Finding shows, and is not needed within minutes.
	labelingInterval = 24 * time.Hour
)

// labelDaily runs label after delay, then every interval, until ctx is done.
// A failed run is logged, and the next one tries again.
func labelDaily(ctx context.Context, label func(context.Context) (agents.LabelingRun, error), delay, interval time.Duration) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if _, err := label(ctx); err != nil && ctx.Err() == nil {
			log.Printf("cartografo: run failed: %v", err)
		}
		timer.Reset(interval)
	}
}
