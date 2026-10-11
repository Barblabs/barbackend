package main

import (
	"context"
	"errors"
	"os"

	"barbackend/internal/cmdb"
	"barbackend/internal/cmdb/itop"
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
	db, err := postgres.Open(ctx, url)
	if err != nil {
		return err
	}
	defer db.Close()
	return run(app{db: db, sources: sources.New(db, providers())})
}

func providers() cmdb.Providers {
	return cmdb.Providers{"itop": itop.Provider{}}
}
