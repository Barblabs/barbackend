package main

import (
	"context"
	"log"

	"barbackend/internal/agents"
)

// planOnNotice runs plan each time w is notified, until ctx is done: after
// each run of the Prioritizer, which runs at least every prioritizeInterval,
// so a run that failed is tried again then (ADR 0034). Notices sent while plan
// runs leave one pending, so it runs once more after. A failed run is logged.
func planOnNotice(ctx context.Context, w wakeup, plan func(context.Context) (agents.PlanningRun, error)) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-w:
		}
		if _, err := plan(ctx); err != nil && ctx.Err() == nil {
			log.Printf("luna: run failed: %v", err)
		}
	}
}
