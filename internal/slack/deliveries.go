package slack

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"barbackend/internal/alert"
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

// errNoChannel is a channel delivery of a Customer whose installation names
// no Security Team channel yet: it waits, as one without an installation
// does.
var errNoChannel = errors.New("no security team channel picked")

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
// claim. Rows of a Customer that has no working installation, and channel
// rows of one that has picked no channel, are left pending: an admin has to
// connect or pick one before they can go.
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
	message, err := render(d)
	if err != nil {
		s.giveUp(ctx, d, failureMalformedPayload, err)
		return true
	}
	switch {
	case d.TargetKind == alert.TargetEmail && d.Target == "":
		s.giveUp(ctx, d, failureOwnerUnreachable, errors.New("the asset has no asset owner"))
		return true
	case d.TargetKind == alert.TargetChannel && d.Target != alert.SecurityTeam:
		s.giveUp(ctx, d, failureMalformedPayload, fmt.Errorf("channel target %q, want %q", d.Target, alert.SecurityTeam))
		return true
	}
	if d.TargetKind == alert.TargetChannel && !s.pace(ctx, d.Customer.String()+"/"+d.Target, lastSent) {
		return false
	}
	installation, token, err := s.sendable(ctx, d.Customer)
	if errors.Is(err, ErrNotInstalled) || errors.Is(err, ErrNeedsReauthorisation) {
		return true
	}
	if err != nil {
		s.retry(ctx, d, failureSlackError, err)
		return true
	}
	message.Channel, err = s.address(ctx, token, installation, d)
	if errors.Is(err, errNoChannel) {
		return true
	}
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
// user id for a DM, and the Security Team channel the installation names now
// for a channel row (ADR 0033).
func (s *Service) address(ctx context.Context, token string, installation postgres.StoredSlackInstallation, d postgres.SlackDelivery) (string, error) {
	if d.TargetKind != alert.TargetChannel {
		return s.client.LookupByEmail(ctx, token, d.Target)
	}
	if installation.ChannelID == "" {
		return "", errNoChannel
	}
	return installation.ChannelID, nil
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
		case authRevoked(api.Code):
			s.giveUp(ctx, d, failureAuthRevoked, cause)
			s.needsReauthorisation(ctx, d.Customer)
			return
		case api.Code == "users_not_found":
			s.giveUp(ctx, d, failureOwnerUnreachable, cause)
			return
		case api.Code == "messages_tab_disabled":
			// The app's own Messages tab is off in its Slack configuration,
			// so no DM can be created until an admin turns it on. Retrying
			// now would only burn the attempts.
			s.giveUp(ctx, d, failureSlackError, cause)
			return
		case channelGone(api.Code):
			s.retry(ctx, d, failureChannelUnreachable, cause)
			return
		}
	}
	s.retry(ctx, d, failureSlackError, cause)
}

// giveUp records a failure no retry fixes; the row stays failed.
func (s *Service) giveUp(ctx context.Context, d postgres.SlackDelivery, code string, cause error) {
	s.record(ctx, d, func(ctx context.Context, tx *postgres.Tx) error {
		return tx.FailSlackDelivery(ctx, d.ID, code, cause.Error())
	})
}

// retry counts a failed attempt and schedules the next one, or gives up with
// code on the last attempt.
func (s *Service) retry(ctx context.Context, d postgres.SlackDelivery, code string, cause error) {
	attempts := d.Attempts + 1
	if attempts >= maxDeliveryAttempts {
		s.giveUp(ctx, d, code, cause)
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
