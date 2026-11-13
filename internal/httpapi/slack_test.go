package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"barbackend/internal/slack"
	"barbackend/internal/slack/slacktest"
	"barbackend/internal/tenancy"
)

type slackStatus struct {
	TeamID      string `json:"team_id"`
	TeamName    string `json:"team_name"`
	ChannelID   string `json:"channel_id"`
	ChannelName string `json:"channel_name"`
	State       string `json:"state"`
}

func (e env) adminToken(t *testing.T) string {
	t.Helper()
	return "Bearer " + e.signIn(t, e.newUser(t, tenancy.CustomerAdmin, e.customer))
}

func (e env) as(token string, req *http.Request) *httptest.ResponseRecorder {
	req.Header.Set("Authorization", token)
	return e.send(req)
}

func (e env) startSlack(t *testing.T, token string) string {
	t.Helper()
	rec := e.as(token, httptest.NewRequest(http.MethodPost, "/slack/install/start", nil))
	got := decode[struct {
		AuthorizeURL string `json:"authorize_url"`
	}](t, rec, http.StatusOK)
	u, err := url.Parse(got.AuthorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatalf("authorize URL %q carries no state", got.AuthorizeURL)
	}
	return state
}

func (e env) callback(t *testing.T, query string) *httptest.ResponseRecorder {
	t.Helper()
	return e.send(httptest.NewRequest(http.MethodGet, "/slack/install/callback?"+query, nil))
}

func (e env) installSlack(t *testing.T, token string) {
	t.Helper()
	state := e.startSlack(t, token)
	rec := e.callback(t, "code="+slacktest.Code+"&state="+url.QueryEscape(state))
	if rec.Code != http.StatusOK {
		t.Fatalf("callback = %d %s, want 200", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "window.close()") {
		t.Errorf("callback body = %q, want it to close the popup", rec.Body)
	}
}

func (e env) slackStatus(t *testing.T, token string) (*slackStatus, string) {
	t.Helper()
	rec := e.as(token, httptest.NewRequest(http.MethodGet, "/slack/installation", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /slack/installation = %d %s, want 200", rec.Code, rec.Body)
	}
	return decode[*slackStatus](t, rec, http.StatusOK), rec.Body.String()
}

func (e env) setSlackChannel(t *testing.T, token, id, name string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"channel_id": id, "channel_name": name})
	return e.as(token, httptest.NewRequest(http.MethodPut, "/slack/installation", bytes.NewReader(body)))
}

func TestSlackInstallThroughThePopup(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	admin := e.adminToken(t)

	if got, body := e.slackStatus(t, admin); got != nil {
		t.Fatalf("status before install = %s, want null", body)
	}

	state := e.startSlack(t, admin)
	rec := e.callback(t, "code="+slacktest.Code+"&state="+url.QueryEscape(state))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "window.close()") {
		t.Fatalf("callback = %d %s, want 200 closing the popup", rec.Code, rec.Body)
	}

	got, _ := e.slackStatus(t, admin)
	if got == nil || got.TeamID != slacktest.TeamID || got.TeamName != slacktest.TeamName || got.State != string(slack.Active) {
		t.Fatalf("status = %+v, want the test workspace active", got)
	}
	var token []byte
	if err := e.conn.QueryRow(context.Background(), "SELECT bot_token FROM slack_installations WHERE customer_id = $1", [16]byte(e.customer)).Scan(&token); err != nil {
		t.Fatal(err)
	}
	if len(token) == 0 || bytes.Contains(token, []byte(slacktest.AccessToken)) {
		t.Errorf("stored token = %x, want ciphertext", token)
	}
	opened, err := e.key.Open(token, []byte(e.customer.String()))
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != slacktest.AccessToken {
		t.Errorf("opened token = %q, want %q", opened, slacktest.AccessToken)
	}
}

func TestSlackCallbackRejectsABadState(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	admin := e.adminToken(t)

	rec := e.callback(t, "code="+slacktest.Code+"&state=not-a-state")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid or has expired") {
		t.Errorf("tampered state = %d %s, want 400 saying the state is invalid", rec.Code, rec.Body)
	}

	state := e.startSlack(t, admin)
	rec = e.callback(t, "state="+url.QueryEscape(state))
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "Slack refused the authorization") {
		t.Errorf("missing code = %d %s, want 502 saying Slack refused", rec.Code, rec.Body)
	}

	rec = e.callback(t, "error=access_denied")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "access_denied") {
		t.Errorf("refused install = %d %s, want 400 naming access_denied", rec.Code, rec.Body)
	}

	if got, body := e.slackStatus(t, admin); got != nil {
		t.Errorf("status after failed callbacks = %s, want null", body)
	}
}

func TestSlackChannelsAreListedAndStored(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	admin := e.adminToken(t)
	e.installSlack(t, admin)
	e.slackAPI.Channels = []slack.Channel{
		{ID: "C1", Name: "general"},
		{ID: "C2", Name: "security", Private: true},
		{ID: "C3", Name: "ops"},
	}
	e.slackAPI.PageSize = 2

	rec := e.as(admin, httptest.NewRequest(http.MethodGet, "/slack/channels", nil))
	got := decode[struct {
		Channels []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			IsPrivate bool   `json:"is_private"`
		} `json:"channels"`
	}](t, rec, http.StatusOK)

	if len(got.Channels) != 3 || got.Channels[1].ID != "C2" || got.Channels[1].Name != "security" {
		t.Errorf("channels = %+v, want all three in order", got.Channels)
	}
	if !got.Channels[1].IsPrivate || got.Channels[0].IsPrivate {
		t.Errorf("channels = %+v, want only security marked private", got.Channels)
	}
	if calls := e.slackAPI.CallsTo("conversations.list"); len(calls) != 2 {
		t.Errorf("conversations.list calls = %d, want 2 pages", len(calls))
	}

	rec = e.setSlackChannel(t, admin, "C2", "security")
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /slack/installation = %d %s, want 200", rec.Code, rec.Body)
	}
	status, _ := e.slackStatus(t, admin)
	if status == nil || status.ChannelID != "C2" || status.ChannelName != "security" {
		t.Errorf("status = %+v, want the stored channel", status)
	}
}

func TestSlackTestMessage(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	admin := e.adminToken(t)
	e.installSlack(t, admin)
	if rec := e.setSlackChannel(t, admin, "C-security", "security"); rec.Code != http.StatusOK {
		t.Fatalf("set channel = %d %s", rec.Code, rec.Body)
	}

	rec := e.as(admin, httptest.NewRequest(http.MethodPost, "/slack/installation/test", nil))
	got := decode[struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}](t, rec, http.StatusOK)
	if !got.OK || got.Error != "" {
		t.Errorf("test = %+v, want ok", got)
	}
	calls := e.slackAPI.CallsTo("chat.postMessage")
	if len(calls) != 1 || calls[0].Form.Get("channel") != "C-security" {
		t.Errorf("chat.postMessage calls = %+v, want one to C-security", calls)
	}

	e.slackAPI.Fail("chat.postMessage", "channel_not_found")
	rec = e.as(admin, httptest.NewRequest(http.MethodPost, "/slack/installation/test", nil))
	got = decode[struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}](t, rec, http.StatusOK)
	if got.OK || got.Error != "channel_not_found" {
		t.Errorf("test = %+v, want Slack's channel_not_found", got)
	}
}

func TestSlackTestMessageNeedsAChannel(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	admin := e.adminToken(t)
	e.installSlack(t, admin)

	rec := e.as(admin, httptest.NewRequest(http.MethodPost, "/slack/installation/test", nil))

	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"code":"slack_channel_not_set"`) {
		t.Errorf("test = %d %s, want 409 slack_channel_not_set", rec.Code, rec.Body)
	}
}

func TestSlackRevokedTokenNeedsReauthorisation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	admin := e.adminToken(t)
	e.installSlack(t, admin)
	if rec := e.setSlackChannel(t, admin, "C-security", "security"); rec.Code != http.StatusOK {
		t.Fatalf("set channel = %d %s", rec.Code, rec.Body)
	}
	e.slackAPI.Fail("chat.postMessage", "invalid_auth")

	rec := e.as(admin, httptest.NewRequest(http.MethodPost, "/slack/installation/test", nil))
	got := decode[struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}](t, rec, http.StatusOK)
	if got.OK || got.Error != "invalid_auth" {
		t.Errorf("test = %+v, want invalid_auth", got)
	}

	status, _ := e.slackStatus(t, admin)
	if status == nil || status.State != string(slack.NeedsReauthorisation) {
		t.Errorf("status = %+v, want needs re-authorisation", status)
	}
	rec = e.as(admin, httptest.NewRequest(http.MethodGet, "/slack/channels", nil))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"code":"slack_needs_reauthorisation"`) {
		t.Errorf("channels = %d %s, want 409 slack_needs_reauthorisation", rec.Code, rec.Body)
	}
}

func TestSlackNeedsAnInstallation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	admin := e.adminToken(t)

	for _, tt := range []struct {
		method string
		path   string
		body   string
		want   int
		code   string
	}{
		{http.MethodGet, "/slack/channels", "", http.StatusNotFound, "slack_not_installed"},
		{http.MethodPut, "/slack/installation", `{"channel_id":"C1","channel_name":"general"}`, http.StatusNotFound, "slack_not_installed"},
		{http.MethodPost, "/slack/installation/test", "", http.StatusNotFound, "slack_not_installed"},
	} {
		var req *http.Request
		if tt.body == "" {
			req = httptest.NewRequest(tt.method, tt.path, nil)
		} else {
			req = httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
		}
		rec := e.as(admin, req)
		if rec.Code != tt.want || !strings.Contains(rec.Body.String(), `"code":"`+tt.code+`"`) {
			t.Errorf("%s %s = %d %s, want %d %s", tt.method, tt.path, rec.Code, rec.Body, tt.want, tt.code)
		}
	}

	rec := e.as(admin, httptest.NewRequest(http.MethodDelete, "/slack/installation", nil))
	if rec.Code != http.StatusNoContent {
		t.Errorf("disconnect without install = %d %s, want 204", rec.Code, rec.Body)
	}
}

func TestSlackDisconnect(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	admin := e.adminToken(t)
	e.installSlack(t, admin)
	if rec := e.setSlackChannel(t, admin, "C-security", "security"); rec.Code != http.StatusOK {
		t.Fatalf("set channel = %d %s", rec.Code, rec.Body)
	}

	rec := e.as(admin, httptest.NewRequest(http.MethodDelete, "/slack/installation", nil))
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("disconnect = %d %s, want 204 with no body", rec.Code, rec.Body)
	}
	if got, body := e.slackStatus(t, admin); got != nil {
		t.Errorf("status after disconnect = %s, want null", body)
	}
	if rec := e.as(admin, httptest.NewRequest(http.MethodDelete, "/slack/installation", nil)); rec.Code != http.StatusNoContent {
		t.Errorf("second disconnect = %d %s, want 204", rec.Code, rec.Body)
	}
}

func TestSlackViewerReadsButCannotManage(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	admin := e.adminToken(t)
	e.installSlack(t, admin)
	if rec := e.setSlackChannel(t, admin, "C-security", "security"); rec.Code != http.StatusOK {
		t.Fatalf("set channel = %d %s", rec.Code, rec.Body)
	}
	viewer := "Bearer " + e.token

	if got, _ := e.slackStatus(t, viewer); got == nil || got.ChannelID != "C-security" {
		t.Errorf("viewer status = %+v, want the installation", got)
	}
	if rec := e.as(viewer, httptest.NewRequest(http.MethodGet, "/slack/channels", nil)); rec.Code != http.StatusOK {
		t.Errorf("viewer channels = %d %s, want 200", rec.Code, rec.Body)
	}
	if got := e.failedDeliveries(t, viewer); len(got) != 0 {
		t.Errorf("viewer failed deliveries = %+v, want none", got)
	}

	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/slack/install/start", nil),
		httptest.NewRequest(http.MethodPut, "/slack/installation", strings.NewReader(`{"channel_id":"C1","channel_name":"general"}`)),
		httptest.NewRequest(http.MethodPost, "/slack/installation/test", nil),
		httptest.NewRequest(http.MethodDelete, "/slack/installation", nil),
		httptest.NewRequest(http.MethodPost, "/slack/deliveries/retry", nil),
	} {
		rec := e.as(viewer, req)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"forbidden"`) {
			t.Errorf("%s %s = %d %s, want 403 forbidden", req.Method, req.URL.Path, rec.Code, rec.Body)
		}
	}
}

func TestSlackPlatformAdminIsForbidden(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	admin := e.adminToken(t)
	e.installSlack(t, admin)
	platform := "Bearer " + e.signIn(t, e.newUser(t, tenancy.PlatformAdmin, tenancy.CustomerID{}))

	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/slack/installation", nil),
		httptest.NewRequest(http.MethodGet, "/slack/channels", nil),
		httptest.NewRequest(http.MethodPost, "/slack/install/start", nil),
		httptest.NewRequest(http.MethodPut, "/slack/installation", strings.NewReader(`{"channel_id":"C1","channel_name":"general"}`)),
		httptest.NewRequest(http.MethodPost, "/slack/installation/test", nil),
		httptest.NewRequest(http.MethodDelete, "/slack/installation", nil),
		httptest.NewRequest(http.MethodGet, "/slack/deliveries/failed", nil),
		httptest.NewRequest(http.MethodPost, "/slack/deliveries/retry", nil),
	} {
		rec := e.as(platform, req)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"forbidden"`) {
			t.Errorf("%s %s = %d %s, want 403 forbidden", req.Method, req.URL.Path, rec.Code, rec.Body)
		}
	}
}

func TestSlackCallbackNeedsNoToken(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	rec := e.callback(t, "state=not-a-state")

	if rec.Code == http.StatusUnauthorized {
		t.Errorf("callback = %d %s, want the sealed state to be the authorization", rec.Code, rec.Body)
	}
}

func TestSlackSetChannelRejectsAnEmptyChannel(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	admin := e.adminToken(t)
	e.installSlack(t, admin)

	for _, body := range []string{
		`{"channel_id":"","channel_name":"general"}`,
		`{"channel_id":"   ","channel_name":"general"}`,
	} {
		rec := e.as(admin, httptest.NewRequest(http.MethodPut, "/slack/installation", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"code":"invalid_request"`) {
			t.Errorf("body %s = %d %s, want 400 invalid_request", body, rec.Code, rec.Body)
		}
	}
}

type failedDelivery struct {
	Kind        string `json:"kind"`
	TargetKind  string `json:"target_kind"`
	Target      string `json:"target"`
	Attempts    int    `json:"attempts"`
	FailureCode string `json:"failure_code"`
	LastError   string `json:"last_error"`
	CreatedAt   string `json:"created_at"`
}

func (e env) queueDelivery(t *testing.T, customer tenancy.CustomerID, targetKind, target, status, failureCode string) {
	t.Helper()
	_, err := e.conn.Exec(context.Background(), `
		INSERT INTO slack_deliveries (customer_id, kind, target_kind, target, payload, status, attempts, failure_code, last_error)
		VALUES ($1, 'finding', $2, $3, '{"cve":"CVE-2026-0001","asset":"web-01"}', $4, 3, $5, 'slack said no')`,
		[16]byte(customer), targetKind, target, status, failureCode)
	if err != nil {
		t.Fatal(err)
	}
}

func (e env) failedDeliveries(t *testing.T, token string) []failedDelivery {
	t.Helper()
	rec := e.as(token, httptest.NewRequest(http.MethodGet, "/slack/deliveries/failed", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /slack/deliveries/failed = %d %s, want 200", rec.Code, rec.Body)
	}
	return decode[struct {
		Deliveries []failedDelivery `json:"deliveries"`
	}](t, rec, http.StatusOK).Deliveries
}

func (e env) retryDeliveries(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()
	return e.as(token, httptest.NewRequest(http.MethodPost, "/slack/deliveries/retry", nil))
}

func TestSlackFailedDeliveriesAreListed(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.queueDelivery(t, e.customer, "email", "owner@example.com", "failed", "owner_unreachable")
	e.queueDelivery(t, e.customer, "channel", "C-security", "failed", "channel_unreachable")
	e.queueDelivery(t, e.customer, "channel", "C-security", "pending", "")

	got := e.failedDeliveries(t, "Bearer "+e.token)

	if len(got) != 2 {
		t.Fatalf("failed deliveries = %d %+v, want the two failed rows", len(got), got)
	}
	byTarget := map[string]failedDelivery{}
	for _, d := range got {
		byTarget[d.Target] = d
	}
	if d := byTarget["owner@example.com"]; d.TargetKind != "email" || d.Kind != "finding" || d.FailureCode != "owner_unreachable" || d.Attempts != 3 || d.LastError == "" || d.CreatedAt == "" {
		t.Errorf("DM row = %+v, want the failed DM with its code and error", d)
	}
	if d := byTarget["C-security"]; d.TargetKind != "channel" || d.FailureCode != "channel_unreachable" {
		t.Errorf("channel row = %+v, want the failed channel copy", d)
	}
}

func TestSlackRetryReturnsFailedRowsToPending(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	admin := e.adminToken(t)
	e.queueDelivery(t, e.customer, "channel", "C-security", "failed", "channel_unreachable")
	e.queueDelivery(t, e.customer, "channel", "C-other", "failed", "malformed_payload")

	rec := e.retryDeliveries(t, admin)

	got := decode[struct {
		Retried int64 `json:"retried"`
	}](t, rec, http.StatusOK)
	if got.Retried != 1 {
		t.Errorf("retried = %d, want only the row a retry can fix", got.Retried)
	}
	if left := e.failedDeliveries(t, admin); len(left) != 1 || left[0].FailureCode != "malformed_payload" {
		t.Errorf("failed after retry = %+v, want only the malformed payload", left)
	}
	var status string
	var attempts int
	if err := e.conn.QueryRow(context.Background(),
		"SELECT status, attempts FROM slack_deliveries WHERE target = 'C-security'").Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || attempts != 0 {
		t.Errorf("retried row = %s/%d, want pending/0", status, attempts)
	}
}

func TestSlackFailedDeliveriesStayInsideTheCustomer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	other := e.newCustomer(t)
	e.queueDelivery(t, other, "channel", "C-theirs", "failed", "channel_unreachable")

	if got := e.failedDeliveries(t, "Bearer "+e.token); len(got) != 0 {
		t.Errorf("failed deliveries = %+v, want none of another customer's", got)
	}
	rec := e.retryDeliveries(t, e.adminToken(t))
	if got := decode[struct {
		Retried int64 `json:"retried"`
	}](t, rec, http.StatusOK); got.Retried != 0 {
		t.Errorf("retried = %d, want none of another customer's", got.Retried)
	}
	var status string
	if err := e.conn.QueryRow(context.Background(),
		"SELECT status FROM slack_deliveries WHERE target = 'C-theirs'").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Errorf("other customer's row = %s, want it untouched", status)
	}
}
