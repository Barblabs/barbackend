package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// runPrioritizer runs prioritizeOnChange with fn until it stops, and fails
// the test when it does not stop within a few seconds.
func runPrioritizer(t *testing.T, ctx context.Context, w wakeup, fn func(context.Context) error, quiet, maxWait, interval time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		prioritizeOnChange(ctx, w, fn, quiet, maxWait, interval)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("prioritizeOnChange did not stop when its context was done")
	}
}

func TestABurstOfChangesMakesOneRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := newWakeup()
	var runs atomic.Int32
	for range 50 {
		w.notify()
	}

	runPrioritizer(t, ctx, w, func(context.Context) error {
		runs.Add(1)
		cancel()
		return nil
	}, 20*time.Millisecond, time.Hour, time.Hour)

	if got := runs.Load(); got != 1 {
		t.Errorf("runs = %d, want 1 for a burst of notices", got)
	}
}

func TestChangesThatKeepComingRunOnceMaxWaitPassed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := newWakeup()
	w.notify()
	go func() {
		for ctx.Err() == nil {
			w.notify()
			time.Sleep(time.Millisecond)
		}
	}()
	started := time.Now()
	var ran time.Duration

	runPrioritizer(t, ctx, w, func(context.Context) error {
		ran = time.Since(started)
		cancel()
		return nil
	}, time.Hour, 30*time.Millisecond, time.Hour)

	if ran == 0 || ran > time.Second {
		t.Errorf("ran after %v, want soon after maxWait though changes kept coming", ran)
	}
}

func TestWithoutChangesItRunsEveryIntervalAndAFailureDoesNotStopIt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var runs atomic.Int32

	runPrioritizer(t, ctx, newWakeup(), func(context.Context) error {
		if runs.Add(1) == 2 {
			cancel()
		}
		return errors.New("a failed run does not stop the next")
	}, time.Hour, time.Hour, 10*time.Millisecond)

	if got := runs.Load(); got != 2 {
		t.Errorf("runs = %d, want 2", got)
	}
}

func TestItDoesNotRunBeforeAChangeOrTheInterval(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var runs atomic.Int32

	runPrioritizer(t, ctx, newWakeup(), func(context.Context) error {
		runs.Add(1)
		return nil
	}, time.Millisecond, time.Millisecond, time.Hour)

	if got := runs.Load(); got != 0 {
		t.Errorf("runs = %d, want none", got)
	}
}
