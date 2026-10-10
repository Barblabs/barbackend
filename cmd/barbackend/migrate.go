package main

import (
	"context"
)

func migrate(ctx context.Context) error {
	db, err := openDB(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Migrate(ctx)
}
