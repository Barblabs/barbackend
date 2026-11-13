package slack_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/slack"
	"barbackend/internal/slack/slacktest"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func newDeliveryEnv(t *testing.T) (*slack.Service, *slacktest.Server, *postgres.DB, *pgx.Conn, tenancy.CustomerID) {
	t.Helper()
	url := pgtest.URL(t)
	db, err := postgres.Open(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	fake := slacktest.New(t)
	customer := newCustomer(t, db)
	return slack.New(db, fake.Client, testKey(t)), fake, db, pgtest.Conn(t, url), customer
}

func finding() map[string]any {
	return map[string]any{
		"cve":            "CVE-2026-1234",
		"asset":          "web-01",
		"portal_url":     "https://portal.test/findings/1",
		"owner_email":    "owner@example.com",
		"score":          87.5,
		"score_band":     "High",
		"kev":            true,
		"epss":           0.42,
		"cvss":           9.8,
		"criticality":    "high",
		"exposure":       "internet",
		"recommendation": "Patch to 2.1.0.",
	}
}

func enqueue(t *testing.T, conn *pgx.Conn, customer tenancy.CustomerID, targetKind, target string, payload map[string]any) uuid.UUID {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	err = conn.QueryRow(context.Background(), `
		INSERT INTO slack_deliveries (customer_id, kind, target_kind, target, payload)
		VALUES ($1, 'finding', $2, $3, $4)
		RETURNING id`, customer, targetKind, target, raw).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type row struct {
	status      string
	attempts    int
	failureCode *string
	lastError   *string
	next        time.Time
}

func deliveryRow(t *testing.T, conn *pgx.Conn, id uuid.UUID) row {
	t.Helper()
	var r row
	err := conn.QueryRow(context.Background(), `
		SELECT status, attempts, failure_code, last_error, next_attempt_at
		FROM slack_deliveries WHERE id = $1`, id).
		Scan(&r.status, &r.attempts, &r.failureCode, &r.lastError, &r.next)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func hasDeliveryRow(t *testing.T, conn *pgx.Conn, id uuid.UUID) bool {
	t.Helper()
	var exists bool
	if err := conn.QueryRow(context.Background(),
		"SELECT exists (SELECT 1 FROM slack_deliveries WHERE id = $1)", id).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func makeDue(t *testing.T, conn *pgx.Conn, id uuid.UUID) {
	t.Helper()
	if _, err := conn.Exec(context.Background(),
		"UPDATE slack_deliveries SET next_attempt_at = now() - interval '1 second' WHERE id = $1", id); err != nil {
		t.Fatal(err)
	}
}

func deliver(t *testing.T, svc *slack.Service) {
	t.Helper()
	if err := svc.DeliverDue(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDeliverDueSendsADMAndDeletesItAtTheNextPoll(t *testing.T) {
	t.Parallel()
	svc, fake, _, conn, customer := newDeliveryEnv(t)
	install(t, svc, adminOf(customer))
	id := enqueue(t, conn, customer, "email", "owner@example.com", finding())

	deliver(t, svc)

	lookups := fake.CallsTo("users.lookupByEmail")
	if len(lookups) != 1 || lookups[0].Query.Get("email") != "owner@example.com" {
		t.Fatalf("lookups = %+v, want owner@example.com", lookups)
	}
	posts := fake.CallsTo("chat.postMessage")
	if len(posts) != 1 || posts[0].Form.Get("channel") != "U-owner" {
		t.Fatalf("posts = %+v, want a DM to U-owner", posts)
	}
	if got := deliveryRow(t, conn, id); got.status != "sent" {
		t.Fatalf("status = %s, want sent", got.status)
	}

	deliver(t, svc)

	if hasDeliveryRow(t, conn, id) {
		t.Fatal("row survived the next poll")
	}
}

func TestDeliverDueSendsTheChannelCopyIdentically(t *testing.T) {
	t.Parallel()
	svc, fake, _, conn, customer := newDeliveryEnv(t)
	install(t, svc, adminOf(customer))
	payload := finding()
	enqueue(t, conn, customer, "email", "owner@example.com", payload)
	enqueue(t, conn, customer, "channel", "C-security", payload)

	deliver(t, svc)

	posts := fake.CallsTo("chat.postMessage")
	if len(posts) != 2 {
		t.Fatalf("posts = %d, want the DM and the channel copy", len(posts))
	}
	byChannel := map[string]string{}
	for _, p := range posts {
		byChannel[p.Form.Get("channel")] = p.Form.Get("blocks")
	}
	if byChannel["U-owner"] == "" || byChannel["U-owner"] != byChannel["C-security"] {
		t.Errorf("blocks differ between the DM and the channel copy:\nDM: %s\nchannel: %s",
			byChannel["U-owner"], byChannel["C-security"])
	}
	if !strings.Contains(byChannel["C-security"], "owner@example.com") {
		t.Errorf("channel copy does not name the owner: %s", byChannel["C-security"])
	}
}

func TestDeliverDueKeepsAChannelsOrder(t *testing.T) {
	t.Parallel()
	svc, fake, _, conn, customer := newDeliveryEnv(t)
	install(t, svc, adminOf(customer))
	first := finding()
	first["cve"] = "CVE-2026-0001"
	second := finding()
	second["cve"] = "CVE-2026-0002"
	enqueue(t, conn, customer, "channel", "C-security", first)
	enqueue(t, conn, customer, "channel", "C-security", second)

	deliver(t, svc)

	posts := fake.CallsTo("chat.postMessage")
	if len(posts) != 2 {
		t.Fatalf("posts = %d, want 2", len(posts))
	}
	if !strings.Contains(posts[0].Form.Get("text"), "CVE-2026-0001") || !strings.Contains(posts[1].Form.Get("text"), "CVE-2026-0002") {
		t.Errorf("order = %q then %q, want 0001 then 0002", posts[0].Form.Get("text"), posts[1].Form.Get("text"))
	}
}

func TestDeliverDueHonoursRetryAfterWithoutCountingAnAttempt(t *testing.T) {
	t.Parallel()
	svc, fake, _, conn, customer := newDeliveryEnv(t)
	install(t, svc, adminOf(customer))
	id := enqueue(t, conn, customer, "channel", "C-security", finding())
	fake.RateLimit("chat.postMessage", 30)

	deliver(t, svc)

	got := deliveryRow(t, conn, id)
	if got.status != "pending" || got.attempts != 0 {
		t.Fatalf("row = %s/%d, want pending/0", got.status, got.attempts)
	}
	if wait := time.Until(got.next); wait < 25*time.Second || wait > 35*time.Second {
		t.Errorf("next attempt in %s, want about 30s", wait)
	}

	fake.RateLimit("chat.postMessage", 0)
	makeDue(t, conn, id)
	deliver(t, svc)

	if got := deliveryRow(t, conn, id); got.status != "sent" {
		t.Fatalf("status = %s, want sent after the rate limit clears", got.status)
	}
}

func TestDeliverDueRetriesTransientFailuresThenGivesUp(t *testing.T) {
	t.Parallel()
	svc, fake, _, conn, customer := newDeliveryEnv(t)
	install(t, svc, adminOf(customer))
	id := enqueue(t, conn, customer, "channel", "C-security", finding())
	fake.Fail("chat.postMessage", "internal_error")

	deliver(t, svc)
	got := deliveryRow(t, conn, id)
	if got.status != "pending" || got.attempts != 1 {
		t.Fatalf("after one failure = %s/%d, want pending/1", got.status, got.attempts)
	}
	if wait := time.Until(got.next); wait < 50*time.Second || wait > 70*time.Second {
		t.Errorf("first retry in %s, want about a minute", wait)
	}

	makeDue(t, conn, id)
	deliver(t, svc)
	got = deliveryRow(t, conn, id)
	if got.status != "pending" || got.attempts != 2 {
		t.Fatalf("after two failures = %s/%d, want pending/2", got.status, got.attempts)
	}
	if wait := time.Until(got.next); wait < 4*time.Minute || wait > 6*time.Minute {
		t.Errorf("second retry in %s, want about five minutes", wait)
	}

	makeDue(t, conn, id)
	deliver(t, svc)
	got = deliveryRow(t, conn, id)
	if got.status != "failed" || got.attempts != 3 || got.failureCode == nil || *got.failureCode != "slack_error" {
		t.Fatalf("after three failures = %s/%d/%v, want failed/3/slack_error", got.status, got.attempts, got.failureCode)
	}
	if got.lastError == nil || *got.lastError == "" {
		t.Error("last_error is empty")
	}
}

func TestDeliverDueFailsAnUnknownOwnerAtOnce(t *testing.T) {
	t.Parallel()
	svc, _, _, conn, customer := newDeliveryEnv(t)
	install(t, svc, adminOf(customer))
	id := enqueue(t, conn, customer, "email", "stranger@example.com", finding())

	deliver(t, svc)

	got := deliveryRow(t, conn, id)
	if got.status != "failed" || got.attempts != 1 || got.failureCode == nil || *got.failureCode != "owner_unreachable" {
		t.Fatalf("row = %s/%d/%v, want failed/1/owner_unreachable", got.status, got.attempts, got.failureCode)
	}
}

func TestDeliverDueFailsAnOwnerWhoseMessagesTabIsDisabled(t *testing.T) {
	t.Parallel()
	svc, fake, _, conn, customer := newDeliveryEnv(t)
	install(t, svc, adminOf(customer))
	id := enqueue(t, conn, customer, "email", "owner@example.com", finding())
	fake.Fail("users.lookupByEmail", "messages_tab_disabled")

	deliver(t, svc)

	got := deliveryRow(t, conn, id)
	if got.status != "failed" || got.attempts != 1 || got.failureCode == nil || *got.failureCode != "slack_error" {
		t.Fatalf("row = %s/%d/%v, want failed/1/slack_error", got.status, got.attempts, got.failureCode)
	}
}

func TestDeliverDueFailsAMalformedPayloadAtOnce(t *testing.T) {
	t.Parallel()
	svc, fake, _, conn, customer := newDeliveryEnv(t)
	install(t, svc, adminOf(customer))
	id := enqueue(t, conn, customer, "channel", "C-security", map[string]any{"asset": "web-01"})

	deliver(t, svc)

	got := deliveryRow(t, conn, id)
	if got.status != "failed" || got.attempts != 1 || got.failureCode == nil || *got.failureCode != "malformed_payload" {
		t.Fatalf("row = %s/%d/%v, want failed/1/malformed_payload", got.status, got.attempts, got.failureCode)
	}
	if posts := fake.CallsTo("chat.postMessage"); len(posts) != 0 {
		t.Errorf("posted a malformed payload %d times", len(posts))
	}
}

func TestDeliverDueFlipsTheInstallationWhenSlackRevokesTheToken(t *testing.T) {
	t.Parallel()
	svc, fake, db, conn, customer := newDeliveryEnv(t)
	install(t, svc, adminOf(customer))
	id := enqueue(t, conn, customer, "channel", "C-security", finding())
	fake.Fail("chat.postMessage", "invalid_auth")

	deliver(t, svc)

	got := deliveryRow(t, conn, id)
	if got.status != "failed" || got.failureCode == nil || *got.failureCode != "auth_revoked" {
		t.Fatalf("row = %s/%v, want failed/auth_revoked", got.status, got.failureCode)
	}
	if state := storedInstallation(t, db, customer).State; state != "needs re-authorisation" {
		t.Errorf("installation state = %q, want needs re-authorisation", state)
	}
}

func TestDeliverDueLeavesRowsPendingWithoutAWorkingInstallation(t *testing.T) {
	t.Parallel()
	svc, fake, _, conn, customer := newDeliveryEnv(t)
	id := enqueue(t, conn, customer, "channel", "C-security", finding())

	deliver(t, svc)

	got := deliveryRow(t, conn, id)
	if got.status != "pending" || got.attempts != 0 {
		t.Fatalf("row = %s/%d, want pending/0", got.status, got.attempts)
	}
	if posts := fake.CallsTo("chat.postMessage"); len(posts) != 0 {
		t.Errorf("posted without an installation %d times", len(posts))
	}
}

func TestDeliverDueNeverInsertsRows(t *testing.T) {
	t.Parallel()
	svc, _, _, conn, customer := newDeliveryEnv(t)
	install(t, svc, adminOf(customer))
	enqueue(t, conn, customer, "channel", "C-security", finding())

	deliver(t, svc)
	deliver(t, svc)

	var count int
	if err := conn.QueryRow(context.Background(), "SELECT count(*) FROM slack_deliveries").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rows left = %d, want the module to only send and delete", count)
	}
}
