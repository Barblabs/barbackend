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

// app is everything a command may depend on, wired in one place.
type app struct {
	db      *postgres.DB
	sources *sources.Service
}

// withApp opens the database only once the command has parsed its
// arguments, so a usage error never waits on or reports a database error.
func withApp(ctx context.Context, run func(app) error) error {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return errors.New("DATABASE_URL is not set")
	}
	key, err := encryptionKey()
	if err != nil {
		return err
	}
	db, err := postgres.Open(ctx, url)
	if err != nil {
		return err
	}
	defer db.Close()
	return run(app{db: db, sources: sources.New(db, providers(), key)})
}

// encryptionKey allows an unset key, so that a Sync without one is recorded
// as a failed Sync Run, but refuses a malformed one at startup.
func encryptionKey() (encryption.Key, error) {
	encoded := os.Getenv("CREDENTIALS_KEY")
	if encoded == "" {
		return encryption.Key{}, nil
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
