package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewsHourlyDigestsEvenWhenTheReaderFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var reads, digests atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		newsHourly(ctx, func(context.Context) error {
			reads.Add(1)
			return errors.New("the model is unavailable")
		}, func(context.Context) error {
			if digests.Add(1) == 2 {
				cancel()
			}
			return nil
		}, 10*time.Millisecond, 10*time.Millisecond)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("newsHourly did not stop when its context was done")
	}
	if r, d := reads.Load(), digests.Load(); r != 2 || d != 2 {
		t.Errorf("reads, digests = %d, %d; want 2 and 2", r, d)
	}
}

func TestNewsHourlyDoesNotRunBeforeTheDelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var runs atomic.Int32
	run := func(context.Context) error { runs.Add(1); return nil }

	newsHourly(ctx, run, run, time.Hour, time.Hour)

	if got := runs.Load(); got != 0 {
		t.Errorf("runs = %d, want none before the delay", got)
	}
}
