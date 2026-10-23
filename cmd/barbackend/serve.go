package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"barbackend/internal/httpapi"
	"barbackend/internal/inventory"
	"github.com/google/uuid"
)

const (
	// readHeaderTimeout stops clients that send headers slowly from holding
	// connections open.
	readHeaderTimeout = 10 * time.Second
	shutdownTimeout   = 10 * time.Second
	syncTimeout       = 5 * time.Minute
)

func serve(ctx context.Context, _ []string) error {
	customer, err := customerID()
	if err != nil {
		return err
	}
	return withApp(ctx, func(a app) error {
		return listen(ctx, httpapi.New(httpapi.Config{
			Sources:        a.sources,
			Customer:       customer,
			AllowedOrigins: allowedOrigins(),
			Lifetime:       ctx,
			SyncTimeout:    syncTimeout,
		}))
	})
}

func listen(ctx context.Context, handler http.Handler) error {
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
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// customerID is the Customer every request acts for until authentication
// exists. Only local development may serve with it.
func customerID() (inventory.CustomerID, error) {
	id, err := uuid.Parse(os.Getenv("CUSTOMER_ID"))
	if err != nil {
		return inventory.CustomerID{}, fmt.Errorf("CUSTOMER_ID: %w", err)
	}
	return inventory.CustomerID(id), nil
}

// allowedOrigins reads CORS_ALLOWED_ORIGINS, a comma-separated list.
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
