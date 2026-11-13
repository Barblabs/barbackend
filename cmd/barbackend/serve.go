package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"barbackend/internal/advisories"
	"barbackend/internal/agents"
	"barbackend/internal/areas"
	"barbackend/internal/assets"
	"barbackend/internal/businesscontext"
	"barbackend/internal/cmdb"
	"barbackend/internal/findings"
	"barbackend/internal/httpapi"
	"barbackend/internal/ingest"
	"barbackend/internal/postgres"
	"barbackend/internal/scoring"
	"barbackend/internal/slack"
	"barbackend/internal/techniques"
	"barbackend/internal/users"
)

const (
	readHeaderTimeout  = 10 * time.Second
	shutdownTimeout    = 10 * time.Second
	syncTimeout        = 5 * time.Minute
	invitationInterval = 10 * time.Second
)

func serve(ctx context.Context, _ []string) error {
	key, err := encryptionKey()
	if err != nil {
		return err
	}
	pool, err := cognitoPool()
	if err != nil {
		return err
	}
	verifier, err := pool.verifier(ctx)
	if err != nil {
		return err
	}
	admin, err := pool.admin(ctx)
	if err != nil {
		return err
	}
	slackAPI, err := newSlackClient()
	if err != nil {
		return err
	}

	return withDB(ctx, func(db *postgres.DB) error {
		// What changes a Customer's Findings, or how they are weighed, wakes
		// the Prioritizer (ADR 0026): Feeds, Syncs, a Business Context save,
		// a User's Feedback on the order and a Cartógrafo run that labeled.
		changed := newWakeup()
		found := findings.New(db, scoring.Model2, kevMaxAge)
		found.OnChanged(changed.notify)
		businessContext := businesscontext.New(db)
		businessContext.OnSaved(changed.notify)
		svc, err := ingest.New(handledBy(found, advisories.New(db), techniques.New(db), registeredFeeds())...)
		if err != nil {
			return err
		}
		agentService := agents.NewService(db, newCrew())
		userService := users.New(db, verifier, admin)
		agentService.OnOrderFeedback(changed.notify)
		label := func(ctx context.Context) (agents.LabelingRun, error) {
			run, err := agentService.LabelVulnerabilities(ctx)
			if run.Labeled > 0 {
				changed.notify()
			}
			return run, err
		}
		// The Feeds, the Cartógrafo, the Prioritizer and the Invitations run
		// in the background, and all stop before the database closes.
		backgroundDone := make(chan struct{})
		go func() {
			defer close(backgroundDone)
			var wg sync.WaitGroup
			wg.Go(func() { svc.Run(ctx) })
			wg.Go(func() { labelDaily(ctx, label, labelingDelay, labelingInterval) })
			wg.Go(func() {
				prioritizeOnChange(ctx, changed, agentService.PrioritizeAll, prioritizeQuiet, prioritizeMaxWait, prioritizeInterval)
			})
			wg.Go(func() { userService.SendInvitations(ctx, invitationInterval) })
			wg.Wait()
		}()
		sources := cmdb.New(db, providers(), key, ctx, syncTimeout)
		sources.OnSynced(found.AfterSync)
		return listen(ctx, backgroundDone, httpapi.New(httpapi.Config{
			Agents:          agentService,
			Areas:           areas.New(db),
			Assets:          assets.New(db, found),
			BusinessContext: businessContext,
			CMDB:            sources,
			Slack:           slack.New(db, slackAPI, key),
			Users:           users.New(db, verifier, admin),
			AllowedOrigins:  allowedOrigins(),
		}))
	})
}

func listen(ctx context.Context, backgroundDone <-chan struct{}, handler http.Handler) error {
	srv := &http.Server{
		Addr:              listenAddr(),
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()
	log.Printf("serving HTTP on %s", srv.Addr)

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	select {
	case <-backgroundDone:
	case <-shutdownCtx.Done():
		return errors.New("the feeds, the cartografo, the prioritizer or the invitations did not stop")
	}
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func allowedOrigins() []string {
	var origins []string
	for o := range strings.SplitSeq(os.Getenv("CORS_ALLOWED_ORIGINS"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			origins = append(origins, o)
		}
	}
	return origins
}

func listenAddr() string {
	if port := os.Getenv("PORT"); port != "" {
		return ":" + port
	}
	return ":8080"
}
