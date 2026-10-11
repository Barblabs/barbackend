package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
)

type command struct {
	name    string
	summary string
	// synopsis is the command line after "barbackend", shown when the
	// command takes arguments.
	synopsis string
	run      func(ctx context.Context, args []string) error
}

var commands = []command{
	{name: "serve", summary: "run the HTTP server", run: serve},
	{name: "migrate", summary: "apply database migrations", run: migrate},
	{name: "source", summary: "add a CMDB Source", synopsis: sourceSynopsis, run: source},
	{name: "sync", summary: "sync a CMDB Source", synopsis: syncSynopsis, run: syncSource},
}

func usage() string {
	var b strings.Builder
	b.WriteString("usage: barbackend <command>\n\ncommands:\n")
	for _, c := range commands {
		line := c.summary
		if c.synopsis != "" {
			line += ": " + c.synopsis
		}
		fmt.Fprintf(&b, "  %-10s%s\n", c.name, line)
	}
	b.WriteString("\nmigrate, source and sync need DATABASE_URL.")
	return b.String()
}

func lookup(name string) (command, bool) {
	for _, c := range commands {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage())
		os.Exit(2)
	}
	cmd, ok := lookup(os.Args[1])
	if !ok {
		fmt.Fprintln(os.Stderr, usage())
		os.Exit(2)
	}
	// Canceling on interrupt lets an interrupted Sync record its failed run
	// and the server shut down gracefully.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := cmd.run(ctx, os.Args[2:]); err != nil {
		log.Fatalf("%s: %v", cmd.name, err)
	}
}
