package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"barbackend/internal/cmdb"
	"barbackend/internal/cmdb/itop"
	"barbackend/internal/encryption"
	"barbackend/internal/postgres"
	"barbackend/internal/sources"
)

type app struct {
	sources *sources.Service
}

func withApp(ctx context.Context, run func(app) error) error {
	key, err := encryptionKey()
	if err != nil {
		return err
	}
	return withDB(ctx, func(db *postgres.DB) error {
		return run(app{sources: sources.New(db, providers(), key)})
	})
}

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

func providers() cmdb.Providers {
	return cmdb.Providers{"itop": itop.Provider{}}
}
