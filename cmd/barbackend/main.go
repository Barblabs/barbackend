package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

type command struct {
	name     string
	summary  string
	synopsis string
	needsDB  bool
	run      func(ctx context.Context, args []string) error
}

var commands = []command{
	{name: "serve", summary: "run the HTTP server", needsDB: true, run: serve},
	{name: "feed", summary: "pull threat-intelligence Feeds", synopsis: feedSynopsis, run: feed},
	{name: "migrate", summary: "apply database migrations", needsDB: true, run: migrate},
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
	var needDB []string
	for _, c := range commands {
		if c.needsDB {
			needDB = append(needDB, c.name)
		}
	}
	fmt.Fprintf(&b, "\n%s need DATABASE_URL.", joinAnd(needDB))
	return b.String()
}

func joinAnd(names []string) string {
	if len(names) <= 1 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cmd.run(ctx, os.Args[2:]); err != nil {
		log.Fatalf("%s: %v", cmd.name, err)
	}
}
