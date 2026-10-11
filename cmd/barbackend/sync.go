package main

import (
	"context"
	"flag"
	"fmt"

	"barbackend/internal/inventory"
	"github.com/google/uuid"
)

const syncSynopsis = "sync --source <uuid>"

func syncSource(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("sync", flag.ExitOnError)
	source := flags.String("source", "", "`uuid` of the CMDB Source to sync")
	_ = flags.Parse(args)

	id, err := uuid.Parse(*source)
	if err != nil {
		return fmt.Errorf("--source: %w", err)
	}
	return withApp(ctx, func(a app) error {
		run, err := a.sources.Sync(ctx, inventory.CMDBSourceID(id))
		if err != nil {
			return err
		}
		c := run.Counts()
		fmt.Println(run.Outcome())
		fmt.Printf("created %d, updated %d, deactivated %d, reactivated %d, skipped %d\n",
			c.Created, c.Updated, c.Deactivated, c.Reactivated, c.Skipped)
		for _, rej := range run.Skipped() {
			fmt.Printf("skipped %s: %s\n", rej.RecordID, rej.Reason)
		}
		return nil
	})
}
