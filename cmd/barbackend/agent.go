package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"barbackend/internal/agents"
	"barbackend/internal/assessment"
	"barbackend/internal/claude"
	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"barbackend/internal/users"
	"github.com/google/uuid"
)

const agentSynopsis = "run --findings <file> [--plans] | prioritize --as <email> | plan --as <email> --prioritization <id> --finding <id> | ask --as <email> [--conversation <id>] <message> | label"

func newCrew() *agents.Crew {
	return agents.NewCrew(claude.New("", ""), agents.ModelsFrom(os.Getenv))
}

func agent(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: barbackend agent " + agentSynopsis)
	}
	switch args[0] {
	case "run":
		return agentRun(ctx, os.Stdout, args[1:])
	case "prioritize":
		return agentPrioritize(ctx, os.Stdout, args[1:])
	case "plan":
		return agentPlan(ctx, os.Stdout, args[1:])
	case "ask":
		return agentAsk(ctx, os.Stdout, args[1:])
	case "label":
		return agentLabel(ctx, os.Stdout, args[1:])
	default:
		return errors.New("usage: barbackend agent " + agentSynopsis)
	}
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

// agentRun orders the Findings of a file anew, as a Customer's first round
// does without a Business Context, and with plans also has Luna write the
// Action Plan of each, in the order to attend them. It stores nothing, so
// prompts and models can be compared on the same Findings.
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
	p, err := crew.Prioritize(ctx, agents.Round{Findings: findings})
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
	var plans []agents.Plan
	for _, g := range p.List.Groups {
		for _, id := range g.Findings() {
			d, _ := p.Finding(id)
			run, err := crew.Plan(ctx, d)
			if err != nil {
				return nil, err
			}
			plans = append(plans, agents.Plan{Finding: id, Dossier: d, Luna: run})
		}
	}
	return plans, nil
}

// agentPrioritize runs the rounds the Customer of a User needs, as serve does
// when Findings change, and writes its newest Prioritization.
func agentPrioritize(ctx context.Context, out io.Writer, args []string) error {
	flags := flag.NewFlagSet("agent prioritize", flag.ExitOnError)
	email := flags.String("as", "", "`email` of a User of the Customer to prioritize")
	_ = flags.Parse(args)
	if *email == "" {
		return errors.New("usage: barbackend agent prioritize --as <email>")
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
		svc := agents.NewService(db, newCrew())
		stored, err := svc.Prioritize(ctx, customer)
		if err != nil {
			return err
		}
		p, err := svc.Latest(ctx, caller)
		if errors.Is(err, agents.ErrPrioritizationNotFound) {
			return errors.New("the Customer has no open Finding with a Score to prioritize")
		}
		if err != nil {
			return err
		}
		return writeJSON(out, map[string]any{"stored": stored, "id": p.ID, "prioritization": p})
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

// agentLabel runs the Cartógrafo once, as serve does every day, on the stored
// Vulnerabilities it has not labeled, within the same daily cap (ADR 0024).
func agentLabel(ctx context.Context, out io.Writer, args []string) error {
	if len(args) > 0 {
		return errors.New("usage: barbackend agent label")
	}
	return withDB(ctx, func(db *postgres.DB) error {
		return labelOnce(ctx, out, agents.NewService(db, newCrew()).LabelVulnerabilities)
	})
}

// labelOnce runs label and writes how many Vulnerabilities each outcome had,
// those of a run that stopped too.
func labelOnce(ctx context.Context, out io.Writer, label func(context.Context) (agents.LabelingRun, error)) error {
	run, err := label(ctx)
	if writeErr := writeJSON(out, run); writeErr != nil {
		return errors.Join(err, writeErr)
	}
	return err
}

func writeJSON(out io.Writer, v any) error {
	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}
