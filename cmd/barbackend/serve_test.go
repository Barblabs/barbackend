package main

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestListenStopsTheBackgroundWhenTheServerCannotStart(t *testing.T) {
	taken, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = taken.Close() })
	t.Setenv("PORT", strconv.Itoa(taken.Addr().(*net.TCPAddr).Port))

	ctx, stopBackground := context.WithCancel(t.Context())
	defer stopBackground()
	backgroundDone := make(chan struct{})
	go func() {
		defer close(backgroundDone)
		<-ctx.Done()
	}()

	returned := make(chan error, 1)
	go func() { returned <- listen(ctx, stopBackground, backgroundDone, http.NotFoundHandler()) }()
	select {
	case err := <-returned:
		if err == nil {
			t.Fatal("listen on a taken port returned no error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listen on a taken port did not return")
	}
	select {
	case <-backgroundDone:
	default:
		t.Fatal("listen returned before the background stopped")
	}
}
