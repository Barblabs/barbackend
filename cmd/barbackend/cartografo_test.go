package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"barbackend/internal/agents"
)

func TestLabelDailyRunsAfterTheDelayThenEveryIntervalUntilStopped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var runs atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		labelDaily(ctx, func(context.Context) (agents.LabelingRun, error) {
			if runs.Add(1) == 3 {
				cancel()
			}
			return agents.LabelingRun{}, errors.New("a failed run does not stop the next")
		}, 10*time.Millisecond, 10*time.Millisecond)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("labelDaily did not stop when its context was done")
	}
	if got := runs.Load(); got != 3 {
		t.Errorf("runs = %d, want 3", got)
	}
}

func TestLabelDailyDoesNotRunBeforeTheDelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var runs atomic.Int32

	labelDaily(ctx, func(context.Context) (agents.LabelingRun, error) {
		runs.Add(1)
		return agents.LabelingRun{}, nil
	}, time.Hour, time.Hour)

	if got := runs.Load(); got != 0 {
		t.Errorf("runs = %d, want none before the delay", got)
	}
}
