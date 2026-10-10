package main

import (
	"context"
	"fmt"
	"log"
	"os"
)

const usage = `usage: barbackend <command>

commands:
  serve     run the HTTP server
  migrate   apply database migrations (needs DATABASE_URL)`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve()
	case "migrate":
		err = migrate(context.Background())
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("%s: %v", os.Args[1], err)
	}
}
