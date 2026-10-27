package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"barbackend/internal/users"
)

func createPlatformAdmin(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: barbackend create-platform-admin <email>")
	}
	p, err := cognitoPool()
	if err != nil {
		return err
	}
	admin, err := p.admin(ctx)
	if err != nil {
		return err
	}
	return withDB(ctx, func(db *postgres.DB) error {
		u, err := users.New(db, nil, admin).Create(ctx, args[0], tenancy.PlatformAdmin, tenancy.CustomerID{})
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stdout, "invited platform admin %s (%s)\n", u.Email(), u.ID())
		return nil
	})
}
