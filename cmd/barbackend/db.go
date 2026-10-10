package main

import (
	"context"
	"errors"
	"os"

	"barbackend/internal/postgres"
)

func openDB(ctx context.Context) (*postgres.DB, error) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return nil, errors.New("DATABASE_URL is not set")
	}
	return postgres.Open(ctx, url)
}
