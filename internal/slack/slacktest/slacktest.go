// Package slacktest stands in for the Slack Web API in tests: it serves the
// endpoints the app calls over httptest, records every call, and can refuse
// one with a Slack error. No test calls Slack.
package slacktest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"

	"barbackend/internal/slack"
)

const (
	ClientID     = "test-slack-client"
	ClientSecret = "test-slack-secret" //nolint:gosec // a test fixture, never a real secret
	RedirectURI  = "https://portal.test/slack/callback"
	Code         = "test-code"
	AccessToken  = "xoxb-test-token" //nolint:gosec // a test fixture, never a real token
	TeamID       = "T-test"
	TeamName     = "Test Workspace"
)

// Call is one request the app made to the fake.
type Call struct {
	Method        string
	Path          string
	Query         url.Values
	Form          url.Values
	Authorization string
}

type Server struct {
	URL    string
	Client *slack.Client
	// Channels is what conversations.list returns, in order.
	Channels []slack.Channel
	// PageSize is how many Channels one conversations.list page holds.
	PageSize int
	// OAuthError, when set, is Slack refusing the code exchange.
	OAuthError string

	mu    sync.Mutex
	fail  map[string]string
	calls []Call
}

func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{
		Channels: []slack.Channel{{ID: "C-general", Name: "general"}},
		PageSize: 200,
		fail:     map[string]string{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth.v2.access", s.oauth)
	mux.HandleFunc("/conversations.list", s.listChannels)
	mux.HandleFunc("/chat.postMessage", s.postMessage)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	s.URL = srv.URL
	s.Client = slack.NewClient(slack.ClientConfig{
		ClientID:     ClientID,
		ClientSecret: ClientSecret,
		RedirectURI:  RedirectURI,
		BaseURL:      srv.URL,
		AuthorizeURL: srv.URL + "/oauth/v2/authorize",
	})
	return s
}

// Fail makes method answer ok false with code, as Slack does.
func (s *Server) Fail(method, code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail[method] = code
}

// Calls is every request the app made, in order.
func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Call(nil), s.calls...)
}

// CallsTo is the requests the app made to one method, such as
// chat.postMessage.
func (s *Server) CallsTo(method string) []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Call
	for _, c := range s.calls {
		if c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

func (s *Server) failure(method string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fail[method]
}

func (s *Server) record(r *http.Request) {
	_ = r.ParseForm()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, Call{
		Method:        r.URL.Path[1:],
		Path:          r.URL.Path,
		Query:         r.URL.Query(),
		Form:          r.PostForm,
		Authorization: r.Header.Get("Authorization"),
	})
}

func (s *Server) oauth(w http.ResponseWriter, r *http.Request) {
	s.record(r)
	if s.OAuthError != "" {
		write(w, map[string]any{"ok": false, "error": s.OAuthError})
		return
	}
	switch {
	case r.FormValue("client_id") != ClientID:
		write(w, map[string]any{"ok": false, "error": "invalid_client_id"})
	case r.FormValue("client_secret") != ClientSecret:
		write(w, map[string]any{"ok": false, "error": "bad_client_secret"})
	case r.FormValue("redirect_uri") != RedirectURI:
		write(w, map[string]any{"ok": false, "error": "bad_redirect_uri"})
	case r.FormValue("code") != Code:
		write(w, map[string]any{"ok": false, "error": "invalid_code"})
	default:
		write(w, map[string]any{
			"ok":           true,
			"access_token": AccessToken,
			"token_type":   "bot",
			"scope":        slack.Scopes,
			"team":         map[string]string{"id": TeamID, "name": TeamName},
		})
	}
}

func (s *Server) listChannels(w http.ResponseWriter, r *http.Request) {
	s.record(r)
	if code := s.failure("conversations.list"); code != "" {
		write(w, map[string]any{"ok": false, "error": code})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+AccessToken {
		write(w, map[string]any{"ok": false, "error": "invalid_auth"})
		return
	}
	start := 0
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		start, _ = strconv.Atoi(cursor)
	}
	end := min(start+s.PageSize, len(s.Channels))
	next := ""
	if end < len(s.Channels) {
		next = strconv.Itoa(end)
	}
	write(w, map[string]any{
		"ok":                true,
		"channels":          s.Channels[start:end],
		"response_metadata": map[string]string{"next_cursor": next},
	})
}

func (s *Server) postMessage(w http.ResponseWriter, r *http.Request) {
	s.record(r)
	if code := s.failure("chat.postMessage"); code != "" {
		write(w, map[string]any{"ok": false, "error": code})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+AccessToken {
		write(w, map[string]any{"ok": false, "error": "invalid_auth"})
		return
	}
	write(w, map[string]any{"ok": true, "channel": r.FormValue("channel"), "ts": "1.0"})
}

func write(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}
