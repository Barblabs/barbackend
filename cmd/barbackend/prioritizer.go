package main

import (
	"context"
	"log"
	"time"
)

const (
	// prioritizeQuiet is how long the Prioritizer waits after the last change
	// before it runs, so the batches of one Feed pull make one round, not one
	// each (ADR 0026).
	prioritizeQuiet = 2 * time.Minute
	// prioritizeMaxWait bounds that wait while changes keep coming, as when
	// EPSS sends its catalog in hundreds of batches.
	prioritizeMaxWait = 15 * time.Minute
	// prioritizeInterval is how often it runs without any change, so a round
	// that failed is tried again.
	prioritizeInterval = 6 * time.Hour
)

// wakeup is a change notice that coalesces: notices sent while one is pending
// leave that one pending.
type wakeup chan struct{}

func newWakeup() wakeup { return make(wakeup, 1) }

// notify never blocks.
func (w wakeup) notify() {
	select {
	case w <- struct{}{}:
	default:
	}
}

// prioritizeOnChange runs prioritize once the changes notified on w have
// stopped for quiet, or maxWait after the first of them, and also after
// interval without a change, until ctx is done. A failed run is logged, and
// the next one tries again.
func prioritizeOnChange(ctx context.Context, w wakeup, prioritize func(context.Context) error, quiet, maxWait, interval time.Duration) {
	idle := time.NewTimer(interval)
	defer idle.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w:
			if !settle(ctx, w, quiet, maxWait) {
				return
			}
		case <-idle.C:
		}
		if err := prioritize(ctx); err != nil && ctx.Err() == nil {
			log.Printf("prioritizer: run failed: %v", err)
		}
		idle.Reset(interval)
	}
}

// settle waits until no change is notified on w for quiet, or until maxWait
// passed, and reports false when ctx is done first.
func settle(ctx context.Context, w wakeup, quiet, maxWait time.Duration) bool {
	deadline := time.NewTimer(maxWait)
	defer deadline.Stop()
	calm := time.NewTimer(quiet)
	defer calm.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-w:
			calm.Reset(quiet)
		case <-calm.C:
			return true
		case <-deadline.C:
			return true
		}
	}
}
