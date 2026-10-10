package main

import (
	"context"
	"errors"
	"os"

	"barbackend/internal/postgres"
)

func migrate(ctx context.Context) error {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return errors.New("DATABASE_URL is not set")
	}
	db, err := postgres.Open(ctx, url)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Migrate(ctx)
}
