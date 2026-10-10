package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
)

const usage = `usage: barbackend <command>

commands:
  serve     run the HTTP server
  migrate   apply database migrations
  source    add a CMDB Source: source add --customer <uuid> --provider <id> --settings '<json>'
  sync      sync a CMDB Source: sync --source <uuid>

migrate, source and sync need DATABASE_URL.`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	// Canceling on interrupt lets an interrupted Sync record its failed run.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve()
	case "migrate":
		err = migrate(ctx)
	case "source":
		err = source(ctx, args)
	case "sync":
		err = syncSource(ctx, args)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("%s: %v", os.Args[1], err)
	}
}
