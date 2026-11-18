package slack_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"barbackend/internal/alert"
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

// finding is an Alert about a new Finding, as the Prioritizer writes it.
func finding() alert.Finding {
	return alert.Finding{
		Finding: uuid.NewString(), Prioritization: uuid.NewString(), Reason: alert.New,
		CVE: "CVE-2026-1234", Asset: "web-01", Component: "nginx 1.18.0",
		OwnerEmail: "owner@example.com", PortalURL: "https://portal.test",
		Score: 0.875, Band: "critical", CVSS: ptr(9.8), EPSS: ptr(0.42), KEV: true,
		Criticality: "high", Exposure: "internet_facing", Lifecycle: "production", Classification: "confidential",
		Group: alert.Group{Position: 1, Of: 3, Title: "Exposed and exploited", Reason: "In KEV and facing the internet."},
	}
}

func ptr[T any](v T) *T { return &v }

func enqueue(t *testing.T, conn *pgx.Conn, customer tenancy.CustomerID, targetKind, target string, payload any) uuid.UUID {
	t.Helper()
	kind := alert.KindFinding
	if _, batch := payload.(alert.Batch); batch {
		kind = alert.KindBatch
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	err = conn.QueryRow(context.Background(), `
		INSERT INTO slack_deliveries (customer_id, kind, target_kind, target, payload)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`, customer, kind, targetKind, target, raw).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// installWithChannel connects Slack for the Customer and picks C-security as
// its Security Team channel.
func installWithChannel(t *testing.T, svc *slack.Service, customer tenancy.CustomerID) {
	t.Helper()
	install(t, svc, adminOf(customer))
	if _, err := svc.SetChannel(context.Background(), adminOf(customer), "C-security", "security"); err != nil {
		t.Fatal(err)
	}
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
	installWithChannel(t, svc, customer)
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
	installWithChannel(t, svc, customer)
	payload := finding()
	enqueue(t, conn, customer, "email", "owner@example.com", payload)
	enqueue(t, conn, customer, "channel", alert.SecurityTeam, payload)

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
	installWithChannel(t, svc, customer)
	first := finding()
	first.CVE = "CVE-2026-0001"
	second := finding()
	second.CVE = "CVE-2026-0002"
	enqueue(t, conn, customer, "channel", alert.SecurityTeam, first)
	enqueue(t, conn, customer, "channel", alert.SecurityTeam, second)

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
	installWithChannel(t, svc, customer)
	id := enqueue(t, conn, customer, "channel", alert.SecurityTeam, finding())
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
	installWithChannel(t, svc, customer)
	id := enqueue(t, conn, customer, "channel", alert.SecurityTeam, finding())
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
	installWithChannel(t, svc, customer)
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
	installWithChannel(t, svc, customer)
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
	installWithChannel(t, svc, customer)
	id := enqueue(t, conn, customer, "channel", alert.SecurityTeam, map[string]any{"asset": "web-01"})

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
	installWithChannel(t, svc, customer)
	id := enqueue(t, conn, customer, "channel", alert.SecurityTeam, finding())
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
	id := enqueue(t, conn, customer, "channel", alert.SecurityTeam, finding())

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
	installWithChannel(t, svc, customer)
	enqueue(t, conn, customer, "channel", alert.SecurityTeam, finding())

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

// posted is the one message the fake Slack got, as its text and blocks.
func posted(t *testing.T, fake *slacktest.Server) (text, blocks string) {
	t.Helper()
	posts := fake.CallsTo("chat.postMessage")
	if len(posts) != 1 {
		t.Fatalf("posts = %d, want 1", len(posts))
	}
	return posts[0].Form.Get("text"), posts[0].Form.Get("blocks")
}

func containsAll(t *testing.T, got string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("message lacks %q:\n%s", w, got)
		}
	}
}

func TestAnAlertShowsItsBandScoreWhyAndTheAsset(t *testing.T) {
	t.Parallel()
	svc, fake, _, conn, customer := newDeliveryEnv(t)
	installWithChannel(t, svc, customer)
	enqueue(t, conn, customer, "channel", alert.SecurityTeam, finding())

	deliver(t, svc)

	text, blocks := posted(t, fake)
	if text != "CRITICAL · CVE-2026-1234 on web-01: 88 / 100" {
		t.Errorf("text = %q", text)
	}
	containsAll(t, blocks, ":red_circle: CRITICAL · CVE-2026-1234 on web-01", "New finding",
		"*Score*\\n88 / 100", "*CVSS*\\n9.8", "*EPSS*\\n42.0%", "*CISA KEV*\\nYes",
		"*Asset* · nginx 1.18.0", "*Criticality*\\nHigh", "*Exposure*\\nInternet-facing", "*Lifecycle*\\nProduction", "*Information classification*\\nConfidential",
		"*Why it matters* · Priority group 1 of 3: Exposed and exploited", "In KEV and facing the internet.",
		"Owner: owner@example.com", "https://portal.test|Open in barbattack")
}

func TestAnAlertOfARisenBandSaysFromWhich(t *testing.T) {
	t.Parallel()
	svc, fake, _, conn, customer := newDeliveryEnv(t)
	installWithChannel(t, svc, customer)
	a := finding()
	a.Reason, a.BandWas, a.CVSS, a.EPSS, a.Exposure, a.Classification = alert.BandRose, "high", nil, nil, "unknown", "unclassified"
	enqueue(t, conn, customer, "channel", alert.SecurityTeam, a)

	deliver(t, svc)

	_, blocks := posted(t, fake)
	containsAll(t, blocks, "Band rose from High to Critical", "*CVSS*\\nUnknown", "*EPSS*\\nPending", "*Exposure*\\nUnknown", "*Information classification*\\nUnclassified")
}

func TestABatchIsOneMessageWithALinePerFinding(t *testing.T) {
	t.Parallel()
	svc, fake, _, conn, customer := newDeliveryEnv(t)
	installWithChannel(t, svc, customer)
	high := finding()
	high.CVE, high.Band, high.Score, high.KEV, high.OwnerEmail = "CVE-2026-0002", "high", 0.61, false, ""
	enqueue(t, conn, customer, "channel", alert.SecurityTeam, alert.Batch{Findings: []alert.Finding{finding(), high}})

	deliver(t, svc)

	text, blocks := posted(t, fake)
	if text != "2 findings · initial load · 1 critical, 1 high" {
		t.Errorf("text = %q", text)
	}
	containsAll(t, blocks, ":red_circle: *88*  *CVE-2026-1234* on web-01 · #1 Exposed and exploited",
		"CVSS 9.8 · EPSS 42.0% · KEV · High · Internet-facing · Production · Confidential · Owner: owner@example.com",
		":large_orange_circle: *61*  *CVE-2026-0002* on web-01", "no KEV", "Owner: —", "Open in barbattack")
}

func TestAChannelAlertWaitsForAChannelAndGoesToTheOnePickedWhenSent(t *testing.T) {
	t.Parallel()
	svc, fake, _, conn, customer := newDeliveryEnv(t)
	install(t, svc, adminOf(customer))
	id := enqueue(t, conn, customer, "channel", alert.SecurityTeam, finding())

	deliver(t, svc)

	if got := deliveryRow(t, conn, id); got.status != "pending" || got.attempts != 0 {
		t.Fatalf("row = %s/%d, want pending/0 until a channel is picked", got.status, got.attempts)
	}
	if posts := fake.CallsTo("chat.postMessage"); len(posts) != 0 {
		t.Fatalf("posted %d times without a channel", len(posts))
	}
	if _, err := svc.SetChannel(t.Context(), adminOf(customer), "C-picked", "picked"); err != nil {
		t.Fatal(err)
	}
	makeDue(t, conn, id)

	deliver(t, svc)

	if posts := fake.CallsTo("chat.postMessage"); len(posts) != 1 || posts[0].Form.Get("channel") != "C-picked" {
		t.Errorf("posts = %+v, want one to C-picked", posts)
	}
}

func TestADMWithoutAnAssetOwnerFailsAtOnceWithoutAskingSlack(t *testing.T) {
	t.Parallel()
	svc, fake, _, conn, customer := newDeliveryEnv(t)
	installWithChannel(t, svc, customer)
	id := enqueue(t, conn, customer, "email", "", finding())

	deliver(t, svc)

	got := deliveryRow(t, conn, id)
	if got.status != "failed" || got.attempts != 1 || got.failureCode == nil || *got.failureCode != "owner_unreachable" {
		t.Fatalf("row = %s/%d/%v, want failed/1/owner_unreachable", got.status, got.attempts, got.failureCode)
	}
	if calls := len(fake.CallsTo("users.lookupByEmail")) + len(fake.CallsTo("chat.postMessage")); calls != 0 {
		t.Errorf("asked Slack %d times", calls)
	}
}

func TestAChannelAlertToAnotherTargetIsMalformed(t *testing.T) {
	t.Parallel()
	svc, fake, _, conn, customer := newDeliveryEnv(t)
	installWithChannel(t, svc, customer)
	id := enqueue(t, conn, customer, "channel", "C-elsewhere", finding())

	deliver(t, svc)

	if got := deliveryRow(t, conn, id); got.status != "failed" || got.failureCode == nil || *got.failureCode != "malformed_payload" {
		t.Fatalf("row = %s/%v, want failed/malformed_payload", got.status, got.failureCode)
	}
	if posts := fake.CallsTo("chat.postMessage"); len(posts) != 0 {
		t.Errorf("posted %d times", len(posts))
	}
}

func TestABatchOfMoreThanTenIsMalformed(t *testing.T) {
	t.Parallel()
	svc, _, _, conn, customer := newDeliveryEnv(t)
	installWithChannel(t, svc, customer)
	var many []alert.Finding
	for range alert.BatchSize + 1 {
		many = append(many, finding())
	}
	id := enqueue(t, conn, customer, "channel", alert.SecurityTeam, alert.Batch{Findings: many})

	deliver(t, svc)

	if got := deliveryRow(t, conn, id); got.status != "failed" || got.failureCode == nil || *got.failureCode != "malformed_payload" {
		t.Fatalf("row = %s/%v, want failed/malformed_payload", got.status, got.failureCode)
	}
}

func TestAnAlertEscapesWhatItQuotesSoItCannotMentionOrForgeALink(t *testing.T) {
	t.Parallel()
	svc, fake, _, conn, customer := newDeliveryEnv(t)
	installWithChannel(t, svc, customer)
	a := finding()
	a.Group.Reason = "Versions < 1.2 & > 1.0. <!channel> see <https://evil.test|Open in barbattack>"
	enqueue(t, conn, customer, "channel", alert.SecurityTeam, a)

	deliver(t, svc)

	_, blocks := posted(t, fake)
	var parsed []struct {
		Text *struct{ Text string } `json:"text"`
	}
	if err := json.Unmarshal([]byte(blocks), &parsed); err != nil {
		t.Fatal(err)
	}
	var why string
	for _, b := range parsed {
		if b.Text != nil && strings.HasPrefix(b.Text.Text, "*Why it matters*") {
			why = b.Text.Text
		}
	}
	if !strings.Contains(why, "Versions &lt; 1.2 &amp; &gt; 1.0. &lt;!channel&gt; see &lt;https://evil.test|Open in barbattack&gt;") {
		t.Errorf("why it matters = %q, want the reason escaped", why)
	}
}

func TestAnAlertStaysWithinSlacksLimits(t *testing.T) {
	t.Parallel()
	svc, fake, _, conn, customer := newDeliveryEnv(t)
	installWithChannel(t, svc, customer)
	a := finding()
	a.Asset = strings.Repeat("a", 200)
	a.Group.Reason = strings.Repeat("<", 4000)
	enqueue(t, conn, customer, "channel", alert.SecurityTeam, a)

	deliver(t, svc)

	_, blocks := posted(t, fake)
	var parsed []struct {
		Type string                 `json:"type"`
		Text *struct{ Text string } `json:"text"`
	}
	if err := json.Unmarshal([]byte(blocks), &parsed); err != nil {
		t.Fatal(err)
	}
	for _, b := range parsed {
		if b.Text == nil {
			continue
		}
		n, limit := utf8.RuneCountInString(b.Text.Text), 3000
		if b.Type == "header" {
			limit = 150
		}
		if n > limit {
			t.Errorf("%s text of %d characters, over Slack's %d", b.Type, n, limit)
		}
		if strings.HasSuffix(strings.TrimSuffix(b.Text.Text, "…"), "&l") || strings.HasSuffix(strings.TrimSuffix(b.Text.Text, "…"), "&lt") {
			t.Errorf("%s text splits an escape: …%s", b.Type, b.Text.Text[len(b.Text.Text)-10:])
		}
	}
}
