package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"

	"barbackend/internal/inventory"
	"barbackend/internal/sources"
	"github.com/google/uuid"
)

const sourceUsage = "usage: barbackend source add --customer <uuid> --provider <id> --settings '<json>'"

func source(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "add" {
		return errors.New(sourceUsage)
	}
	flags := flag.NewFlagSet("source add", flag.ExitOnError)
	customer := flags.String("customer", "", "`uuid` of the Customer the CMDB Source belongs to")
	provider := flags.String("provider", "", "CMDB Provider `id`")
	settings := flags.String("settings", "", "connection settings as `json`, validated by the provider")
	_ = flags.Parse(args[1:])

	customerID, err := uuid.Parse(*customer)
	if err != nil {
		return fmt.Errorf("--customer: %w", err)
	}
	if !json.Valid([]byte(*settings)) {
		return errors.New("--settings is not valid JSON")
	}
	db, err := openDB(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	src, err := sources.New(db, providers()).Add(ctx, inventory.CustomerID(customerID), inventory.CMDBProvider(*provider), json.RawMessage(*settings))
	if err != nil {
		return err
	}
	fmt.Println(src.ID())
	return nil
}
