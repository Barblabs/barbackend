package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"barbackend/internal/agents"
)

// runLuna runs planOnNotice with fn until it stops, and fails the test when
// it does not stop within a few seconds.
func runLuna(t *testing.T, ctx context.Context, w wakeup, fn func(context.Context) (agents.PlanningRun, error)) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		planOnNotice(ctx, w, fn)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("planOnNotice did not stop when its context was done")
	}
}

func TestLunaRunsOnceForNoticesSentBeforeSheRuns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := newWakeup()
	for range 5 {
		w.notify()
	}
	var runs atomic.Int32

	runLuna(t, ctx, w, func(context.Context) (agents.PlanningRun, error) {
		runs.Add(1)
		cancel()
		return agents.PlanningRun{}, nil
	})

	if got := runs.Load(); got != 1 {
		t.Errorf("runs = %d, want 1 for notices that coalesced", got)
	}
}

func TestANoticeWhileLunaRunsHasHerRunOnceMoreAndAFailureDoesNotStopHer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := newWakeup()
	w.notify()
	var runs atomic.Int32

	runLuna(t, ctx, w, func(context.Context) (agents.PlanningRun, error) {
		if runs.Add(1) == 2 {
			cancel()
			return agents.PlanningRun{}, nil
		}
		w.notify()
		w.notify()
		return agents.PlanningRun{}, errors.New("a failed run does not stop the next")
	})

	if got := runs.Load(); got != 2 {
		t.Errorf("runs = %d, want 2", got)
	}
}

func TestLunaWaitsForANotice(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var runs atomic.Int32

	runLuna(t, ctx, newWakeup(), func(context.Context) (agents.PlanningRun, error) {
		runs.Add(1)
		return agents.PlanningRun{}, nil
	})

	if got := runs.Load(); got != 0 {
		t.Errorf("runs = %d, want none without a notice", got)
	}
}
