package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"barbackend/internal/agents"
	"barbackend/internal/assessment"
	"barbackend/internal/claude"
	"barbackend/internal/feeds"
	"barbackend/internal/feeds/epss"
	"barbackend/internal/feeds/kev"
	"barbackend/internal/feeds/nvd"
	"barbackend/internal/postgres"
	"barbackend/internal/stixext"
	"barbackend/internal/tenancy"
	"barbackend/internal/users"
	"github.com/TcM1911/stix2"
	"github.com/google/uuid"
)

const agentSynopsis = "finding --asset <file> --component <name> --cve <id> [--id <finding>] | run --findings <file> [--plans] | prioritize --as <email> --findings <file> | plan --as <email> --prioritization <id> --finding <id> | ask --as <email> [--conversation <id>] <message>"

const lookupTimeout = 30 * time.Second

func newCrew() *agents.Crew {
	return agents.NewCrew(claude.New(""), agents.ModelsFrom(os.Getenv))
}

func agent(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: barbackend agent " + agentSynopsis)
	}
	switch args[0] {
	case "finding":
		return agentFinding(ctx, os.Stdout, args[1:])
	case "run":
		return agentRun(ctx, os.Stdout, args[1:])
	case "prioritize":
		return agentPrioritize(ctx, os.Stdout, args[1:])
	case "plan":
		return agentPlan(ctx, os.Stdout, args[1:])
	case "ask":
		return agentAsk(ctx, os.Stdout, args[1:])
	default:
		return errors.New("usage: barbackend agent " + agentSynopsis)
	}
}

// agentFinding stands in for the Findings pipeline until it exists: it builds
// the Dossier of one Finding from the live Feeds, for files that agent run and
// agent prioritize read. The Agents themselves never read a Feed.
func agentFinding(ctx context.Context, out io.Writer, args []string) error {
	flags := flag.NewFlagSet("agent finding", flag.ExitOnError)
	file := flags.String("asset", "", "JSON `file` describing the Asset, as docs/examples/asset.json")
	component := flags.String("component", "", "`name` of the Asset's affected Software Component")
	cve := flags.String("cve", "", "`id` of the CVE")
	id := flags.String("id", "", "`id` of the Finding; the Asset, Component and CVE when empty")
	_ = flags.Parse(args)
	cveID, ok := stixext.CVEID(*cve)
	if *file == "" || *component == "" || !ok {
		return errors.New("usage: barbackend agent finding --asset <file> --component <name> --cve <id> [--id <finding>]")
	}
	raw, err := os.ReadFile(*file) //nolint:gosec // the operator names the file on their own command line
	if err != nil {
		return err
	}
	asset, err := agents.ParseAsset(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", *file, err)
	}
	read := readFeeds(ctx, cveID)
	if !read.Listed() {
		return fmt.Errorf("no Feed lists %s (unavailable: %v)", cveID, read.Unavailable)
	}
	if *id == "" {
		*id = strings.Join([]string{asset.Imported().Name(), *component, cveID}, "/")
	}
	d, err := assessment.NewDossier(*id, cveID, asset, *component, read)
	if err != nil {
		return err
	}
	return writeJSON(out, d)
}

func readFeeds(ctx context.Context, cveID string) assessment.Feeds {
	var read assessment.Feeds
	sources := []struct {
		name   string
		lookup feeds.Lookup
		into   **stix2.Vulnerability
	}{
		{assessment.FeedKEV, kev.New(nil, "").Lookup, &read.KEV},
		{assessment.FeedEPSS, epss.New(nil, "", "").Lookup, &read.EPSS},
		{assessment.FeedNVD, nvd.New(nil, "", os.Getenv("NVD_API_KEY")).Lookup, &read.NVD},
	}
	for _, source := range sources {
		ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
		v, err := source.lookup(ctx, cveID)
		cancel()
		if err != nil {
			log.Printf("agent finding: %s: read %s: %v", cveID, source.name, err)
			read.Unavailable = append(read.Unavailable, source.name)
			continue
		}
		*source.into = v
	}
	return read
}

func readFindings(file string) ([]assessment.Dossier, error) {
	raw, err := os.ReadFile(file) //nolint:gosec // the operator names the file on their own command line
	if err != nil {
		return nil, err
	}
	findings, err := agents.ParseFindings(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return findings, nil
}

// agentRun prioritizes the Findings of a file, and with plans also has Luna
// write the Action Plan of each, in the order to attend them. It stores
// nothing.
func agentRun(ctx context.Context, out io.Writer, args []string) error {
	flags := flag.NewFlagSet("agent run", flag.ExitOnError)
	file := flags.String("findings", "", "JSON `file` of Findings, as docs/examples/findings.json")
	withPlans := flags.Bool("plans", false, "also run Luna on every Finding, one request each")
	_ = flags.Parse(args)
	if *file == "" {
		return errors.New("usage: barbackend agent run --findings <file> [--plans]")
	}
	findings, err := readFindings(*file)
	if err != nil {
		return err
	}
	crew := newCrew()
	p, err := crew.Prioritize(ctx, findings)
	if err != nil {
		return err
	}
	result := struct {
		Prioritization agents.Prioritization `json:"prioritization"`
		Plans          []agents.Plan         `json:"plans,omitempty"`
	}{Prioritization: p}
	if *withPlans {
		if result.Plans, err = planEach(ctx, crew, p); err != nil {
			return err
		}
	}
	if err := writeJSON(out, result); err != nil {
		return err
	}
	if p.Prioritizer.Output == nil {
		return fmt.Errorf("the Prioritizer gave no verified answer: %s", p.Prioritizer.Status)
	}
	return nil
}

// planEach runs Luna on every Finding of p, in the order to attend them.
func planEach(ctx context.Context, crew *agents.Crew, p agents.Prioritization) ([]agents.Plan, error) {
	if p.Prioritizer.Output == nil {
		return nil, nil
	}
	var plans []agents.Plan
	for _, g := range p.Prioritizer.Output.Groups {
		for _, id := range g.Findings {
			run, err := crew.Plan(ctx, p, id)
			if err != nil {
				return nil, err
			}
			plans = append(plans, agents.Plan{Finding: id, Luna: run})
		}
	}
	return plans, nil
}

func agentPrioritize(ctx context.Context, out io.Writer, args []string) error {
	flags := flag.NewFlagSet("agent prioritize", flag.ExitOnError)
	email := flags.String("as", "", "`email` of a User of the Customer whose Findings these are")
	file := flags.String("findings", "", "JSON `file` of Findings, as docs/examples/findings.json")
	_ = flags.Parse(args)
	if *email == "" || *file == "" {
		return errors.New("usage: barbackend agent prioritize --as <email> --findings <file>")
	}
	findings, err := readFindings(*file)
	if err != nil {
		return err
	}
	return withDB(ctx, func(db *postgres.DB) error {
		caller, err := users.New(db, nil, nil).ByEmail(ctx, *email)
		if err != nil {
			return err
		}
		customer, err := caller.ActsFor()
		if err != nil {
			return err
		}
		p, err := agents.NewService(db, newCrew()).Prioritize(ctx, customer, findings)
		if err != nil {
			return err
		}
		return writeJSON(out, map[string]any{"id": p.ID, "prioritization": p})
	})
}

func agentPlan(ctx context.Context, out io.Writer, args []string) error {
	flags := flag.NewFlagSet("agent plan", flag.ExitOnError)
	email := flags.String("as", "", "`email` of the User to act as")
	prioritization := flags.String("prioritization", "", "`id` of the Prioritization")
	finding := flags.String("finding", "", "`id` of the Finding")
	_ = flags.Parse(args)
	id, err := uuid.Parse(*prioritization)
	if err != nil || *email == "" || *finding == "" {
		return errors.New("usage: barbackend agent plan --as <email> --prioritization <id> --finding <id>")
	}
	return withDB(ctx, func(db *postgres.DB) error {
		caller, err := users.New(db, nil, nil).ByEmail(ctx, *email)
		if err != nil {
			return err
		}
		plan, err := agents.NewService(db, newCrew()).Plan(ctx, caller, id, *finding)
		if err != nil {
			return err
		}
		return writeJSON(out, plan)
	})
}

func agentAsk(ctx context.Context, out io.Writer, args []string) error {
	flags := flag.NewFlagSet("agent ask", flag.ExitOnError)
	email := flags.String("as", "", "`email` of the User to act as")
	conversation := flags.String("conversation", "", "`id` of the conversation to continue; a new one when empty")
	_ = flags.Parse(args)
	message := strings.Join(flags.Args(), " ")
	if *email == "" || message == "" {
		return errors.New("usage: barbackend agent ask --as <email> [--conversation <id>] <message>")
	}
	return withDB(ctx, func(db *postgres.DB) error {
		caller, err := users.New(db, nil, nil).ByEmail(ctx, *email)
		if err != nil {
			return err
		}
		answer, err := askAnalista(ctx, agents.NewService(db, newCrew()), caller, *conversation, message)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "%s\n\nconversation: %s\n", answer.Reply, answer.Conversation)
		return err
	})
}

func askAnalista(ctx context.Context, svc *agents.Service, caller tenancy.User, conversation, message string) (agents.Answer, error) {
	if conversation == "" {
		return svc.Ask(ctx, caller, message)
	}
	id, err := uuid.Parse(conversation)
	if err != nil {
		return agents.Answer{}, fmt.Errorf("--conversation: %w", err)
	}
	return svc.Continue(ctx, caller, id, message)
}

func writeJSON(out io.Writer, v any) error {
	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}
