package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"barbackend/internal/cmdb"
	"barbackend/internal/httpapi"
	"barbackend/internal/ingest"
	"barbackend/internal/postgres"
	"barbackend/internal/users"
)

const (
	readHeaderTimeout = 10 * time.Second
	shutdownTimeout   = 10 * time.Second
	syncTimeout       = 5 * time.Minute
)

func serve(ctx context.Context, _ []string) error {
	key, err := encryptionKey()
	if err != nil {
		return err
	}
	pool, err := cognitoPool()
	if err != nil {
		return err
	}
	verifier, err := pool.verifier(ctx)
	if err != nil {
		return err
	}
	admin, err := pool.admin(ctx)
	if err != nil {
		return err
	}

	svc, err := ingest.New(registeredFeeds()...)
	if err != nil {
		return err
	}
	feedsDone := make(chan struct{})
	go func() {
		defer close(feedsDone)
		svc.Run(ctx)
	}()

	return withDB(ctx, func(db *postgres.DB) error {
		return listen(ctx, feedsDone, httpapi.New(httpapi.Config{
			CMDB:           cmdb.New(db, providers(), key, ctx, syncTimeout),
			Users:          users.New(db, verifier, admin),
			AllowedOrigins: allowedOrigins(),
		}))
	})
}

func listen(ctx context.Context, feedsDone <-chan struct{}, handler http.Handler) error {
	srv := &http.Server{
		Addr:              listenAddr(),
		Handler:           handler,
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
	select {
	case <-feedsDone:
	case <-shutdownCtx.Done():
		return errors.New("feeds did not stop")
	}
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func allowedOrigins() []string {
	var origins []string
	for o := range strings.SplitSeq(os.Getenv("CORS_ALLOWED_ORIGINS"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			origins = append(origins, o)
		}
	}
	return origins
}

func listenAddr() string {
	if port := os.Getenv("PORT"); port != "" {
		return ":" + port
	}
	return ":8080"
}
