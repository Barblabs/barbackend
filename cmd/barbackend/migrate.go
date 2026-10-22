package main

import (
	"context"

	"barbackend/internal/postgres"
)

func migrate(ctx context.Context, _ []string) error {
	return withDB(ctx, func(db *postgres.DB) error { return db.Migrate(ctx) })
}
