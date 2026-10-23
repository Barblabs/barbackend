package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"barbackend/internal/inventory"
	"github.com/google/uuid"
)

const sourceSynopsis = "source add --customer <uuid> --provider <id> --settings '<json>' < <credentials json>"

const maxCredentialsSize = 64 << 10

func source(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "add" {
		return errors.New("usage: barbackend " + sourceSynopsis)
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
	if stat, err := os.Stdin.Stat(); err == nil && stat.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprintln(os.Stderr, "credentials as json, then Ctrl-D:")
	}
	credentials, err := readCredentials(os.Stdin)
	if err != nil {
		return err
	}
	return withApp(ctx, func(a app) error {
		src, err := a.sources.Add(ctx, inventory.CustomerID(customerID), inventory.CMDBProvider(*provider), json.RawMessage(*settings), credentials)
		if err != nil {
			return err
		}
		fmt.Println(src.ID())
		return nil
	})
}

func readCredentials(r io.Reader) (json.RawMessage, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxCredentialsSize+1))
	if err != nil {
		return nil, fmt.Errorf("read credentials from stdin: %w", err)
	}
	if len(raw) > maxCredentialsSize {
		return nil, fmt.Errorf("credentials on stdin exceed %d bytes", maxCredentialsSize)
	}
	if !json.Valid(raw) {
		return nil, errors.New("credentials on stdin are not valid JSON")
	}
	return raw, nil
}
