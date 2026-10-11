package main

import "context"

func migrate(ctx context.Context, _ []string) error {
	return withApp(ctx, func(a app) error { return a.db.Migrate(ctx) })
}
