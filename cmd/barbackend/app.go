package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"barbackend/internal/cmdb/provider"
	"barbackend/internal/cmdb/provider/itop"
	"barbackend/internal/encryption"
	"barbackend/internal/postgres"
)

func withDB(ctx context.Context, run func(*postgres.DB) error) error {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return errors.New("DATABASE_URL is not set")
	}
	db, err := postgres.Open(ctx, url)
	if err != nil {
		return err
	}
	defer db.Close()
	return run(db)
}

func encryptionKey() (encryption.Key, error) {
	encoded := os.Getenv("CREDENTIALS_KEY")
	if encoded == "" {
		return encryption.Key{}, errors.New("CREDENTIALS_KEY is not set")
	}
	key, err := encryption.ParseKey(encoded)
	if err != nil {
		return encryption.Key{}, fmt.Errorf("CREDENTIALS_KEY: %w", err)
	}
	return key, nil
}

func providers() provider.Providers {
	return provider.Providers{"itop": itop.Provider{}}
}
