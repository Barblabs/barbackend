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
	"barbackend/internal/newsitems"
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
		ctx, stopBackground := context.WithCancel(ctx)
		defer stopBackground()
		// What changes a Customer's Findings, or how they are weighed, wakes
		// the Prioritizer (ADR 0026): Feeds, Syncs, a Business Context save,
		// a User's Feedback on the order and a Cartógrafo run that labeled.
		changed := newWakeup()
		found := findings.New(db, scoring.Model3, kevMaxAge)
		found.OnChanged(changed.notify)
		businessContext := businesscontext.New(db)
		businessContext.OnSaved(changed.notify)
		svc, err := ingest.New(handledBy(found, advisories.New(db), techniques.New(db), newsitems.New(db), registeredFeeds())...)
		if err != nil {
			return err
		}
		agentService := newAgentService(db)
		userService := users.New(db, verifier, admin)
		agentService.OnOrderFeedback(changed.notify)
		label := func(ctx context.Context) (agents.LabelingRun, error) {
			run, err := agentService.LabelVulnerabilities(ctx)
			if run.Labeled > 0 {
				changed.notify()
			}
			return run, err
		}
		// Each run of the Prioritizer wakes Luna, who writes the Action Plans
		// that its order leaves due (ADR 0034), in her own goroutine, so a
		// long run of hers does not hold the next order back.
		prioritized := newWakeup()
		prioritize := func(ctx context.Context) error {
			err := agentService.PrioritizeAll(ctx)
			prioritized.notify()
			return err
		}
		// The Feeds, the Cartógrafo, the Reader and the Editor, the
		// Prioritizer, Luna, the Invitations and the Slack deliveries run in
		// the background, and all stop before the database closes.
		slackService := slack.New(db, slackAPI, key)
		backgroundDone := make(chan struct{})
		go func() {
			defer close(backgroundDone)
			var wg sync.WaitGroup
			wg.Go(func() { svc.Run(ctx) })
			wg.Go(func() { labelDaily(ctx, label, labelingDelay, labelingInterval) })
			wg.Go(func() {
				read := func(ctx context.Context) error { _, err := agentService.ReadNews(ctx); return err }
				newsHourly(ctx, read, agentService.DigestNews, newsRunDelay, newsRunInterval)
			})
			wg.Go(func() {
				prioritizeOnChange(ctx, changed, prioritize, prioritizeQuiet, prioritizeMaxWait, prioritizeInterval)
			})
			wg.Go(func() { planOnNotice(ctx, prioritized, agentService.PlanAll) })
			wg.Go(func() { userService.SendInvitations(ctx, invitationInterval) })
			wg.Go(func() { slackService.RunDeliveries(ctx) })
			wg.Wait()
		}()
		sources := cmdb.New(db, providers(), key, ctx, syncTimeout)
		sources.OnSynced(found.AfterSync)
		return listen(ctx, stopBackground, backgroundDone, httpapi.New(httpapi.Config{
			Agents:          agentService,
			Areas:           areas.New(db),
			Assets:          assets.New(db, found),
			BusinessContext: businessContext,
			CMDB:            sources,
			Findings:        found,
			Slack:           slackService,
			Users:           userService,
			AllowedOrigins:  allowedOrigins(),
		}))
	})
}

func listen(ctx context.Context, stopBackground context.CancelFunc, backgroundDone <-chan struct{}, handler http.Handler) error {
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
		stopBackground()
		waitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		return errors.Join(err, awaitBackground(waitCtx, backgroundDone))
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := awaitBackground(shutdownCtx, backgroundDone); err != nil {
		return err
	}
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func awaitBackground(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return errors.New("the feeds, the cartografo, the news, the prioritizer, luna, the invitations or the slack deliveries did not stop")
	}
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
