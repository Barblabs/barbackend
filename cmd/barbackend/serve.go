package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"barbackend/internal/httpapi"
)

const (
	// readHeaderTimeout stops clients that send headers slowly from holding
	// connections open.
	readHeaderTimeout = 10 * time.Second
	shutdownTimeout   = 10 * time.Second
)

func serve(ctx context.Context, _ []string) error {
	srv := &http.Server{
		Addr:              listenAddr(),
		Handler:           httpapi.New(),
		ReadHeaderTimeout: readHeaderTimeout,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()
	log.Printf("serving HTTP on %s", srv.Addr)

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func listenAddr() string {
	if port := os.Getenv("PORT"); port != "" {
		return ":" + port
	}
	return ":8080"
}
