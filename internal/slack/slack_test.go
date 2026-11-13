package slack_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"reflect"
	"testing"
	"time"

	"barbackend/internal/encryption"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/slack"
	"barbackend/internal/slack/slacktest"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

func testKey(t *testing.T) encryption.Key {
	t.Helper()
	key, err := encryption.ParseKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newCustomer(t *testing.T, db *postgres.DB) tenancy.CustomerID {
	t.Helper()
	c, err := tenancy.NewCustomer(tenancy.CustomerID(uuid.New()), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.CreateCustomer(context.Background(), c)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return c.ID()
}

func newService(t *testing.T) (*slack.Service, *slacktest.Server, *postgres.DB, tenancy.CustomerID, encryption.Key) {
	t.Helper()
	db := pgtest.NewDB(t)
	fake := slacktest.New(t)
	key := testKey(t)
	return slack.New(db, fake.Client, key), fake, db, newCustomer(t, db), key
}

func adminOf(customer tenancy.CustomerID) tenancy.User {
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "admin@example.com", tenancy.CustomerAdmin, customer)
	if err != nil {
		panic(err)
	}
	return u
}

func viewerOf(customer tenancy.CustomerID) tenancy.User {
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "viewer@example.com", tenancy.Viewer, customer)
	if err != nil {
		panic(err)
	}
	return u
}

func platformAdmin() tenancy.User {
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "platform@example.com", tenancy.PlatformAdmin, tenancy.CustomerID{})
	if err != nil {
		panic(err)
	}
	return u
}

func stateOf(t *testing.T, authorize string) string {
	t.Helper()
	u, err := url.Parse(authorize)
	if err != nil {
		t.Fatal(err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatalf("authorize URL %q carries no state", authorize)
	}
	return state
}

func install(t *testing.T, svc *slack.Service, caller tenancy.User) {
	t.Helper()
	authorize, err := svc.StartInstall(context.Background(), caller)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.HandleCallback(context.Background(), slacktest.Code, stateOf(t, authorize)); err != nil {
		t.Fatal(err)
	}
}

func storedInstallation(t *testing.T, db *postgres.DB, customer tenancy.CustomerID) postgres.StoredSlackInstallation {
	t.Helper()
	stored, err := postgres.InTxValue(context.Background(), db, func(tx *postgres.Tx) (postgres.StoredSlackInstallation, error) {
		return tx.SlackInstallation(context.Background(), customer)
	})
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func setState(t *testing.T, db *postgres.DB, customer tenancy.CustomerID, state slack.State) {
	t.Helper()
	if err := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		return tx.SetSlackState(context.Background(), customer, string(state))
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStartInstallReturnsTheAuthorizeURL(t *testing.T) {
	t.Parallel()
	svc, _, _, customer, _ := newService(t)

	authorize, err := svc.StartInstall(context.Background(), adminOf(customer))
	if err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(authorize)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	for name, want := range map[string]string{
		"client_id":    slacktest.ClientID,
		"scope":        slack.Scopes,
		"redirect_uri": slacktest.RedirectURI,
	} {
		if got := q.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if state := q.Get("state"); state == "" {
		t.Error("state is empty")
	}
}

func TestInstallStoresAnEncryptedToken(t *testing.T) {
	t.Parallel()
	svc, fake, db, customer, key := newService(t)
	caller := adminOf(customer)

	install(t, svc, caller)

	got, err := svc.Status(context.Background(), caller)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.TeamID != slacktest.TeamID || got.TeamName != slacktest.TeamName || got.State != slack.Active {
		t.Fatalf("status = %+v, want the test workspace active", got)
	}
	stored := storedInstallation(t, db, customer)
	if len(stored.BotToken) == 0 || bytes.Contains(stored.BotToken, []byte(slacktest.AccessToken)) {
		t.Errorf("stored token = %x, want ciphertext", stored.BotToken)
	}
	opened, err := key.Open(stored.BotToken, []byte(customer.String()))
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != slacktest.AccessToken {
		t.Errorf("opened token = %q, want %q", opened, slacktest.AccessToken)
	}
	calls := fake.CallsTo("oauth.v2.access")
	if len(calls) != 1 {
		t.Fatalf("oauth calls = %d, want 1", len(calls))
	}
	if calls[0].Form.Get("code") != slacktest.Code || calls[0].Form.Get("client_secret") != slacktest.ClientSecret {
		t.Errorf("oauth form = %v, want the code and the client secret", calls[0].Form)
	}
}

func TestReinstallKeepsTheChannelAndReactivates(t *testing.T) {
	t.Parallel()
	svc, _, db, customer, _ := newService(t)
	caller := adminOf(customer)
	install(t, svc, caller)
	if _, err := svc.SetChannel(context.Background(), caller, "C-security", "security"); err != nil {
		t.Fatal(err)
	}
	setState(t, db, customer, slack.NeedsReauthorisation)

	install(t, svc, caller)

	got, err := svc.Status(context.Background(), caller)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.State != slack.Active || got.ChannelID != "C-security" || got.ChannelName != "security" {
		t.Errorf("status = %+v, want active with the channel kept", got)
	}
}

func TestCallbackRejectsATamperedState(t *testing.T) {
	t.Parallel()
	svc, _, _, customer, _ := newService(t)
	caller := adminOf(customer)
	authorize, err := svc.StartInstall(context.Background(), caller)
	if err != nil {
		t.Fatal(err)
	}
	state := []byte(stateOf(t, authorize))
	if state[len(state)-1] == 'A' {
		state[len(state)-1] = 'B'
	} else {
		state[len(state)-1] = 'A'
	}

	err = svc.HandleCallback(context.Background(), slacktest.Code, string(state))

	if !errors.Is(err, slack.ErrInvalidState) {
		t.Fatalf("err = %v, want ErrInvalidState", err)
	}
	if got, err := svc.Status(context.Background(), caller); err != nil || got != nil {
		t.Errorf("status = %+v, %v, want nothing stored", got, err)
	}
}

func TestCallbackRejectsAnExpiredState(t *testing.T) {
	t.Parallel()
	svc, _, _, customer, _ := newService(t)
	now := time.Date(2026, time.November, 11, 10, 0, 0, 0, time.UTC)
	svc.SetNowForTest(func() time.Time { return now })
	state, err := svc.SealStateForTest(customer)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)

	err = svc.HandleCallback(context.Background(), slacktest.Code, state)

	if !errors.Is(err, slack.ErrInvalidState) {
		t.Fatalf("err = %v, want ErrInvalidState", err)
	}
}

func TestCallbackRejectsAStateSealedWithAnotherKey(t *testing.T) {
	t.Parallel()
	svc, fake, db, customer, _ := newService(t)
	authorize, err := svc.StartInstall(context.Background(), adminOf(customer))
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := encryption.ParseKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	other := slack.New(db, fake.Client, otherKey)

	err = other.HandleCallback(context.Background(), slacktest.Code, stateOf(t, authorize))

	if !errors.Is(err, slack.ErrInvalidState) {
		t.Fatalf("err = %v, want ErrInvalidState", err)
	}
}

func TestChannelsFollowsCursorPagination(t *testing.T) {
	t.Parallel()
	svc, fake, _, customer, _ := newService(t)
	caller := adminOf(customer)
	fake.Channels = []slack.Channel{
		{ID: "C1", Name: "general"},
		{ID: "C2", Name: "security", Private: true},
		{ID: "C3", Name: "ops"},
		{ID: "C4", Name: "random"},
		{ID: "C5", Name: "alerts"},
	}
	fake.PageSize = 2
	install(t, svc, caller)

	got, err := svc.Channels(context.Background(), caller)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(got, fake.Channels) {
		t.Errorf("channels = %+v, want %+v", got, fake.Channels)
	}
	calls := fake.CallsTo("conversations.list")
	if len(calls) != 3 {
		t.Fatalf("conversations.list calls = %d, want 3", len(calls))
	}
	for i, want := range []string{"", "2", "4"} {
		if got := calls[i].Query.Get("cursor"); got != want {
			t.Errorf("call %d cursor = %q, want %q", i, got, want)
		}
	}
	if got := calls[0].Query.Get("types"); got != "public_channel,private_channel" {
		t.Errorf("types = %q, want public and private channels", got)
	}
}

func TestSetChannelNeedsAnInstallation(t *testing.T) {
	t.Parallel()
	svc, _, _, customer, _ := newService(t)

	_, err := svc.SetChannel(context.Background(), adminOf(customer), "C1", "general")

	if !errors.Is(err, slack.ErrNotInstalled) {
		t.Fatalf("err = %v, want ErrNotInstalled", err)
	}
}

func TestSetChannelStoresIt(t *testing.T) {
	t.Parallel()
	svc, _, db, customer, _ := newService(t)
	caller := adminOf(customer)
	install(t, svc, caller)

	got, err := svc.SetChannel(context.Background(), caller, " C-security ", " security ")
	if err != nil {
		t.Fatal(err)
	}

	if got == nil || got.ChannelID != "C-security" || got.ChannelName != "security" {
		t.Errorf("installation = %+v, want the trimmed channel", got)
	}
	stored := storedInstallation(t, db, customer)
	if stored.ChannelID != "C-security" || stored.ChannelName != "security" {
		t.Errorf("stored channel = %q %q, want C-security security", stored.ChannelID, stored.ChannelName)
	}
}

func TestSendTestPostsToTheSecurityTeamChannel(t *testing.T) {
	t.Parallel()
	svc, fake, _, customer, _ := newService(t)
	caller := adminOf(customer)
	install(t, svc, caller)
	if _, err := svc.SetChannel(context.Background(), caller, "C-security", "security"); err != nil {
		t.Fatal(err)
	}

	result, err := svc.SendTest(context.Background(), caller)
	if err != nil {
		t.Fatal(err)
	}

	if !result.OK || result.Error != "" {
		t.Errorf("result = %+v, want ok", result)
	}
	calls := fake.CallsTo("chat.postMessage")
	if len(calls) != 1 {
		t.Fatalf("chat.postMessage calls = %d, want 1", len(calls))
	}
	if got := calls[0].Form.Get("channel"); got != "C-security" {
		t.Errorf("channel = %q, want C-security", got)
	}
	if got := calls[0].Form.Get("text"); got != slack.TestMessage {
		t.Errorf("text = %q, want the test message", got)
	}
}

func TestSendTestWithoutAChannel(t *testing.T) {
	t.Parallel()
	svc, _, _, customer, _ := newService(t)
	caller := adminOf(customer)
	install(t, svc, caller)

	_, err := svc.SendTest(context.Background(), caller)

	if !errors.Is(err, slack.ErrNoChannel) {
		t.Fatalf("err = %v, want ErrNoChannel", err)
	}
}

func TestSendTestReturnsSlacksRefusal(t *testing.T) {
	t.Parallel()
	svc, fake, _, customer, _ := newService(t)
	caller := adminOf(customer)
	install(t, svc, caller)
	if _, err := svc.SetChannel(context.Background(), caller, "C-security", "security"); err != nil {
		t.Fatal(err)
	}
	fake.Fail("chat.postMessage", "channel_not_found")

	result, err := svc.SendTest(context.Background(), caller)

	if err != nil {
		t.Fatal(err)
	}
	if result.OK || result.Error != "channel_not_found" {
		t.Errorf("result = %+v, want Slack's channel_not_found", result)
	}
}

func TestSendTestFlipsARevokedInstallation(t *testing.T) {
	t.Parallel()
	svc, fake, db, customer, _ := newService(t)
	caller := adminOf(customer)
	install(t, svc, caller)
	if _, err := svc.SetChannel(context.Background(), caller, "C-security", "security"); err != nil {
		t.Fatal(err)
	}
	fake.Fail("chat.postMessage", "invalid_auth")

	result, err := svc.SendTest(context.Background(), caller)
	if err != nil {
		t.Fatal(err)
	}
	if result.OK || result.Error != "invalid_auth" {
		t.Errorf("result = %+v, want invalid_auth", result)
	}
	if got := storedInstallation(t, db, customer).State; got != string(slack.NeedsReauthorisation) {
		t.Errorf("state = %q, want needs re-authorisation", got)
	}
	if _, err := svc.Channels(context.Background(), caller); !errors.Is(err, slack.ErrNeedsReauthorisation) {
		t.Errorf("channels err = %v, want ErrNeedsReauthorisation", err)
	}
}

func TestDisconnectHidesTheInstallationAndDropsTheToken(t *testing.T) {
	t.Parallel()
	svc, _, db, customer, _ := newService(t)
	caller := adminOf(customer)
	install(t, svc, caller)

	if err := svc.Disconnect(context.Background(), caller); err != nil {
		t.Fatal(err)
	}

	got, err := svc.Status(context.Background(), caller)
	if err != nil || got != nil {
		t.Errorf("status = %+v, %v, want nothing", got, err)
	}
	stored := storedInstallation(t, db, customer)
	if stored.State != string(slack.Removed) || stored.BotToken != nil || stored.RemovedAt == nil {
		t.Errorf("stored = %+v, want removed with no token", stored)
	}
	if _, err := svc.Channels(context.Background(), caller); !errors.Is(err, slack.ErrNotInstalled) {
		t.Errorf("channels err = %v, want ErrNotInstalled", err)
	}
	if err := svc.Disconnect(context.Background(), caller); err != nil {
		t.Errorf("second disconnect: %v, want it idempotent", err)
	}

	install(t, svc, caller)

	got, err = svc.Status(context.Background(), caller)
	if err != nil || got == nil || got.State != slack.Active {
		t.Errorf("after reinstall status = %+v, %v, want active", got, err)
	}
}

func TestViewerReadsButCannotManageSlack(t *testing.T) {
	t.Parallel()
	svc, _, _, customer, _ := newService(t)
	admin := adminOf(customer)
	viewer := viewerOf(customer)

	if got, err := svc.Status(context.Background(), viewer); err != nil || got != nil {
		t.Errorf("viewer status = %+v, %v, want nothing yet", got, err)
	}
	install(t, svc, admin)
	if _, err := svc.SetChannel(context.Background(), admin, "C-security", "security"); err != nil {
		t.Fatal(err)
	}
	if got, err := svc.Status(context.Background(), viewer); err != nil || got == nil || got.ChannelID != "C-security" {
		t.Errorf("viewer status = %+v, %v, want the channel", got, err)
	}
	if _, err := svc.Channels(context.Background(), viewer); err != nil {
		t.Errorf("viewer channels: %v, want the channels", err)
	}

	if _, err := svc.StartInstall(context.Background(), viewer); !errors.Is(err, tenancy.ErrNotCustomerAdmin) {
		t.Errorf("start err = %v, want ErrNotCustomerAdmin", err)
	}
	if _, err := svc.SetChannel(context.Background(), viewer, "C1", "general"); !errors.Is(err, tenancy.ErrNotCustomerAdmin) {
		t.Errorf("set channel err = %v, want ErrNotCustomerAdmin", err)
	}
	if _, err := svc.SendTest(context.Background(), viewer); !errors.Is(err, tenancy.ErrNotCustomerAdmin) {
		t.Errorf("test err = %v, want ErrNotCustomerAdmin", err)
	}
	if err := svc.Disconnect(context.Background(), viewer); !errors.Is(err, tenancy.ErrNotCustomerAdmin) {
		t.Errorf("disconnect err = %v, want ErrNotCustomerAdmin", err)
	}
}

func TestPlatformAdminCannotSeeSlack(t *testing.T) {
	t.Parallel()
	svc, _, _, customer, _ := newService(t)
	platform := platformAdmin()
	install(t, svc, adminOf(customer))

	if _, err := svc.Status(context.Background(), platform); !errors.Is(err, tenancy.ErrNoCustomer) {
		t.Errorf("status err = %v, want ErrNoCustomer", err)
	}
	if _, err := svc.StartInstall(context.Background(), platform); !errors.Is(err, tenancy.ErrNotCustomerAdmin) {
		t.Errorf("start err = %v, want ErrNotCustomerAdmin", err)
	}
}
