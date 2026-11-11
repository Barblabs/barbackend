package main

import (
	"context"
	"errors"
	"strings"
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

func TestLabelOnceWritesTheOutcomesEvenOfARunThatStopped(t *testing.T) {
	var out strings.Builder
	stopped := errors.New("the model is unavailable")

	err := labelOnce(context.Background(), &out, func(context.Context) (agents.LabelingRun, error) {
		return agents.LabelingRun{Labeled: 2, None: 1}, stopped
	})

	if !errors.Is(err, stopped) {
		t.Errorf("err = %v, want the run's", err)
	}
	for _, want := range []string{`"labeled": 2`, `"none": 1`, `"failed": 0`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output = %s, want %s", out.String(), want)
		}
	}
}
