package slack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
)

const (
	// deliveryInterval is how often serve drains the queue (ADR 0030).
	deliveryInterval = time.Minute
	// deliveryLease keeps a claimed row out of the queue while it is being
	// sent, so a crash reposts it after the lease instead of losing it.
	deliveryLease = time.Minute
	// deliveryPace is Slack's rough limit per channel: about one message a
	// second.
	deliveryPace = time.Second
	// maxDeliveryAttempts is the third failure: after the one-minute and the
	// five-minute retry, the row is given up on.
	maxDeliveryAttempts = 3
)

// Failure codes a failed row carries (ADR 0030).
const (
	failureOwnerUnreachable   = "owner_unreachable"
	failureChannelUnreachable = "channel_unreachable"
	failureAuthRevoked        = "auth_revoked"
	failureMalformedPayload   = "malformed_payload"
	failureSlackError         = "slack_error"
)

// deliveryRetry is how long a failed attempt waits before the next one.
var deliveryRetry = [...]time.Duration{time.Minute, 5 * time.Minute}

// claimResult is one claim attempt's result: a delivery when one is due.
type claimResult struct {
	delivery postgres.SlackDelivery
	due      bool
}

// RunDeliveries drains the queue now and then every minute, until ctx ends.
func (s *Service) RunDeliveries(ctx context.Context) {
	ticker := time.NewTicker(deliveryInterval)
	defer ticker.Stop()
	for {
		if err := s.DeliverDue(ctx); err != nil {
			log.Printf("slack deliveries: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// DeliverDue deletes the rows Slack accepted, then sends every due row it can
// claim. Rows of a Customer that has no working installation are left
// pending: an admin has to reconnect before they can go.
func (s *Service) DeliverDue(ctx context.Context) error {
	if err := s.db.InTx(ctx, func(tx *postgres.Tx) error {
		return tx.DeleteSentSlackDeliveries(ctx)
	}); err != nil {
		return err
	}
	lastSent := map[string]time.Time{}
	for {
		result, err := postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) (claimResult, error) {
			now := s.now()
			delivery, due, err := tx.ClaimSlackDelivery(ctx, now, now.Add(deliveryLease))
			return claimResult{delivery: delivery, due: due}, err
		})
		if err != nil || !result.due {
			return err
		}
		if !s.deliver(ctx, result.delivery, lastSent) {
			return nil
		}
	}
}

// deliver sends one claimed row and records what happened. It reports false
// when ctx ended while pacing.
func (s *Service) deliver(ctx context.Context, d postgres.SlackDelivery, lastSent map[string]time.Time) bool {
	if d.TargetKind == "channel" && !s.pace(ctx, d.Target, lastSent) {
		return false
	}
	message, err := render(d)
	if err != nil {
		s.recordFailure(ctx, d, failureMalformedPayload, err, true)
		return true
	}
	token, err := s.token(ctx, d.Customer)
	if errors.Is(err, ErrNotInstalled) || errors.Is(err, ErrNeedsReauthorisation) {
		return true
	}
	if err != nil {
		s.recordFailure(ctx, d, failureSlackError, err, false)
		return true
	}
	message.Channel, err = s.address(ctx, token, d)
	if err != nil {
		s.recordAPIError(ctx, d, err)
		return true
	}
	if err := s.client.PostMessage(ctx, token, message); err != nil {
		s.recordAPIError(ctx, d, err)
		return true
	}
	s.markSent(ctx, d)
	return true
}

// pace waits out Slack's per-target limit, one message a second. It reports
// false when ctx ended first.
func (s *Service) pace(ctx context.Context, target string, lastSent map[string]time.Time) bool {
	if at, sent := lastSent[target]; sent {
		if wait := deliveryPace - s.now().Sub(at); wait > 0 && !sleep(ctx, wait) {
			return false
		}
	}
	lastSent[target] = s.now()
	return true
}

// address resolves a row's target to where chat.postMessage sends it: a Slack
// user id for a DM, the channel id itself otherwise.
func (s *Service) address(ctx context.Context, token string, d postgres.SlackDelivery) (string, error) {
	if d.TargetKind == "channel" {
		return d.Target, nil
	}
	return s.client.LookupByEmail(ctx, token, d.Target)
}

// markSent records that Slack accepted the message; the next poll deletes it.
func (s *Service) markSent(ctx context.Context, d postgres.SlackDelivery) {
	s.record(ctx, d, func(ctx context.Context, tx *postgres.Tx) error {
		return tx.MarkSlackDeliverySent(ctx, d.ID)
	})
}

// recordAPIError records a Slack refusal: a rate limit delays the row without
// counting an attempt, a revoked token gives up and flips the installation,
// an owner Slack cannot reach gives up at once, and the rest follow the retry
// ladder.
func (s *Service) recordAPIError(ctx context.Context, d postgres.SlackDelivery, cause error) {
	var api *APIError
	if errors.As(cause, &api) {
		switch {
		case api.Status == http.StatusTooManyRequests:
			wait := api.RetryAfter
			if wait <= 0 {
				wait = deliveryInterval
			}
			s.record(ctx, d, func(ctx context.Context, tx *postgres.Tx) error {
				return tx.DelaySlackDelivery(ctx, d.ID, s.now().Add(wait))
			})
			return
		case api.Code == "invalid_auth" || api.Code == "token_revoked":
			s.record(ctx, d, func(ctx context.Context, tx *postgres.Tx) error {
				return tx.FailSlackDelivery(ctx, d.ID, failureAuthRevoked, cause.Error())
			})
			s.needsReauthorisation(ctx, d.Customer)
			return
		case api.Code == "users_not_found":
			s.record(ctx, d, func(ctx context.Context, tx *postgres.Tx) error {
				return tx.FailSlackDelivery(ctx, d.ID, failureOwnerUnreachable, cause.Error())
			})
			return
		case api.Code == "messages_tab_disabled":
			// The app's own Messages tab is off in its Slack configuration,
			// so no DM can be created until an admin turns it on. Retrying
			// now would only burn the attempts.
			s.record(ctx, d, func(ctx context.Context, tx *postgres.Tx) error {
				return tx.FailSlackDelivery(ctx, d.ID, failureSlackError, cause.Error())
			})
			return
		case channelGone(api.Code):
			s.recordFailure(ctx, d, failureChannelUnreachable, cause, false)
			return
		}
	}
	s.recordFailure(ctx, d, failureSlackError, cause, false)
}

// recordFailure counts a failed attempt and either schedules the next one or
// gives up. Terminal failures are recorded once.
func (s *Service) recordFailure(ctx context.Context, d postgres.SlackDelivery, code string, cause error, terminal bool) {
	attempts := d.Attempts + 1
	if terminal || attempts >= maxDeliveryAttempts {
		s.record(ctx, d, func(ctx context.Context, tx *postgres.Tx) error {
			return tx.FailSlackDelivery(ctx, d.ID, code, cause.Error())
		})
		return
	}
	wait := deliveryRetry[min(int(attempts), len(deliveryRetry))-1]
	s.record(ctx, d, func(ctx context.Context, tx *postgres.Tx) error {
		return tx.RescheduleSlackDelivery(ctx, d.ID, s.now().Add(wait), cause.Error())
	})
}

// record writes what happened to a claimed row even while serve is shutting
// down, because losing it would repost a message Slack already accepted.
func (s *Service) record(ctx context.Context, d postgres.SlackDelivery, fn func(context.Context, *postgres.Tx) error) {
	recordCtx := context.WithoutCancel(ctx)
	if err := s.db.InTx(recordCtx, func(tx *postgres.Tx) error { return fn(recordCtx, tx) }); err != nil {
		log.Printf("slack: record delivery %s: %v", d.ID, err)
	}
}

// channelGone reports whether a Slack error means the channel cannot take the
// message as things stand. It is retried because the channel may come back,
// but a human usually has to add the app or unarchive it.
func channelGone(code string) bool {
	switch code {
	case "channel_not_found", "not_in_channel", "is_archived", "channel_is_archived":
		return true
	}
	return false
}

func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// findingPayload is the jsonb contract the pipeline writes for kind=finding
// (ADR 0029). The worker renders it and reads nothing else; EPSS is the
// probability Slack shows as a percentage.
type findingPayload struct {
	CVE            string  `json:"cve"`
	Asset          string  `json:"asset"`
	PortalURL      string  `json:"portal_url"`
	OwnerEmail     string  `json:"owner_email"`
	Score          float64 `json:"score"`
	ScoreBand      string  `json:"score_band"`
	KEV            bool    `json:"kev"`
	EPSS           float64 `json:"epss"`
	CVSS           float64 `json:"cvss"`
	Criticality    string  `json:"criticality"`
	Exposure       string  `json:"exposure"`
	Recommendation string  `json:"recommendation"`
}

type text struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type block struct {
	Type     string  `json:"type"`
	Text     *text   `json:"text,omitempty"`
	Fields   []*text `json:"fields,omitempty"`
	Elements []*text `json:"elements,omitempty"`
}

// render turns a delivery's payload into the one message both the DM and the
// channel copy carry. It fails when the payload is not a finding this worker
// knows how to render.
func render(d postgres.SlackDelivery) (Message, error) {
	if d.Kind != "finding" {
		return Message{}, fmt.Errorf("unknown slack delivery kind %q", d.Kind)
	}
	var p findingPayload
	if err := json.Unmarshal(d.Payload, &p); err != nil {
		return Message{}, fmt.Errorf("decode finding payload: %w", err)
	}
	if p.CVE == "" || p.Asset == "" {
		return Message{}, errors.New("finding payload has no CVE or asset")
	}
	score := strconv.FormatFloat(p.Score, 'f', -1, 64)
	fields := []*text{
		mrkdwn("*Score*\n" + score + " (" + p.ScoreBand + ")"),
		mrkdwn("*KEV*\n" + yesNo(p.KEV)),
		mrkdwn("*EPSS*\n" + strconv.FormatFloat(p.EPSS*100, 'f', 1, 64) + "%"),
		mrkdwn("*CVSS*\n" + strconv.FormatFloat(p.CVSS, 'f', 1, 64)),
		mrkdwn("*Criticality*\n" + orDash(p.Criticality)),
		mrkdwn("*Exposure*\n" + orDash(p.Exposure)),
	}
	blocks := []block{
		{Type: "header", Text: &text{Type: "plain_text", Text: p.CVE + " on " + p.Asset}},
		{Type: "section", Fields: fields},
	}
	if p.Recommendation != "" {
		blocks = append(blocks, block{
			Type: "section",
			Text: mrkdwn("*Recommendation*\n" + p.Recommendation),
		})
	}
	blocks = append(blocks, block{
		Type:     "context",
		Elements: []*text{mrkdwn("Owner: " + orDash(p.OwnerEmail) + " · " + link(p.PortalURL))},
	})
	raw, err := json.Marshal(blocks)
	if err != nil {
		return Message{}, fmt.Errorf("encode slack blocks: %w", err)
	}
	return Message{
		Text:   fmt.Sprintf("%s on %s: %s (%s)", p.CVE, p.Asset, score, p.ScoreBand),
		Blocks: raw,
	}, nil
}

func mrkdwn(s string) *text {
	return &text{Type: "mrkdwn", Text: s}
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func link(url string) string {
	if url == "" {
		return "barbattack"
	}
	return "<" + url + "|Open in barbattack>"
}

// FailedDelivery is a queued message the worker gave up on, as the portal
// lists it.
type FailedDelivery struct {
	Kind        string
	TargetKind  string
	Target      string
	Attempts    int32
	FailureCode string
	LastError   string
	CreatedAt   time.Time
}

// FailedDeliveries lists the Customer's failed rows, oldest first. Every role
// of the Customer may read it.
func (s *Service) FailedDeliveries(ctx context.Context, caller tenancy.User) ([]FailedDelivery, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return nil, err
	}
	rows, err := postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]postgres.FailedSlackDelivery, error) {
		return tx.FailedSlackDeliveries(ctx, customer)
	})
	if err != nil {
		return nil, err
	}
	failed := make([]FailedDelivery, len(rows))
	for i, row := range rows {
		failed[i] = FailedDelivery{
			Kind:        row.Kind,
			TargetKind:  row.TargetKind,
			Target:      row.Target,
			Attempts:    row.Attempts,
			FailureCode: row.FailureCode,
			LastError:   row.LastError,
			CreatedAt:   row.CreatedAt,
		}
	}
	return failed, nil
}

// RetryFailedDeliveries returns the Customer's failed rows to pending, except
// the ones a retry cannot fix, and reports how many it reset. Customer Admin
// only.
func (s *Service) RetryFailedDeliveries(ctx context.Context, caller tenancy.User) (int64, error) {
	customer, err := caller.ManageUsers()
	if err != nil {
		return 0, err
	}
	return postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) (int64, error) {
		return tx.RetryFailedSlackDeliveries(ctx, customer)
	})
}
