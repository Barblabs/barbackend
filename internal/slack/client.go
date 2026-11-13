// Package slack installs the Slack app into a Customer's workspace and sends
// the messages the pipeline queues (ADR 0025). It talks to the Slack Web API
// through Client, so tests can stand in a fake server.
package slack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultBaseURL      = "https://slack.com/api"
	defaultAuthorizeURL = "https://slack.com/oauth/v2/authorize"
	// Scopes is what the app asks for at consent (ADR 0025): post messages,
	// resolve an email to a Slack user, post to a channel by id, list channels
	// for the portal's picker, and read the private channels the app has been
	// added to. users:read rides along because Slack rejects the consent
	// screen with invalid_scope when users:read.email is requested without it.
	Scopes = "chat:write,users:read,users:read.email,chat:write.public,channels:read,groups:read"

	maxPages = 100
)

var (
	// ErrUnavailable is Slack unreachable or answering something other than
	// the Web API's JSON.
	ErrUnavailable = errors.New("slack is unavailable")
	// ErrOAuth is Slack refusing the code exchange.
	ErrOAuth = errors.New("slack rejected the authorization")
)

// APIError is Slack answering ok false, such as invalid_auth or
// channel_not_found. Slack answers these with HTTP 200.
type APIError struct {
	Code   string
	Status int
}

func (e *APIError) Error() string {
	return fmt.Sprintf("slack: %s", e.Code)
}

// ClientConfig is what the app registration gives the server. The URLs are
// overridable so tests can point at a fake.
type ClientConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	BaseURL      string
	AuthorizeURL string
	HTTPClient   *http.Client
}

type Client struct {
	clientID     string
	clientSecret string
	redirectURI  string
	baseURL      string
	authorizeURL string
	http         *http.Client
}

func NewClient(cfg ClientConfig) *Client {
	c := &Client{
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		redirectURI:  cfg.RedirectURI,
		baseURL:      strings.TrimSuffix(cfg.BaseURL, "/"),
		authorizeURL: cfg.AuthorizeURL,
		http:         cfg.HTTPClient,
	}
	if c.baseURL == "" {
		c.baseURL = defaultBaseURL
	}
	if c.authorizeURL == "" {
		c.authorizeURL = defaultAuthorizeURL
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: 10 * time.Second}
	}
	return c
}

// AuthorizeURL is where the portal's popup sends the admin.
func (c *Client) AuthorizeURL(state string) string {
	q := url.Values{
		"client_id":    {c.clientID},
		"scope":        {Scopes},
		"redirect_uri": {c.redirectURI},
		"state":        {state},
	}
	return c.authorizeURL + "?" + q.Encode()
}

// OAuth is what oauth.v2.access returns for a bot installation.
type OAuth struct {
	AccessToken string
	TeamID      string
	TeamName    string
}

type oauthResponse struct {
	envelope
	AccessToken string `json:"access_token"`
	Team        struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"team"`
}

// Exchange turns the code Slack sent the popup into a bot token.
func (c *Client) Exchange(ctx context.Context, code string) (OAuth, error) {
	form := url.Values{
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"code":          {code},
		"redirect_uri":  {c.redirectURI},
	}
	var resp oauthResponse
	if err := c.post(ctx, "", "oauth.v2.access", form, &resp); err != nil {
		return OAuth{}, err
	}
	if resp.AccessToken == "" || resp.Team.ID == "" {
		return OAuth{}, fmt.Errorf("%w: the response carries no bot token or team", ErrOAuth)
	}
	return OAuth{AccessToken: resp.AccessToken, TeamID: resp.Team.ID, TeamName: resp.Team.Name}, nil
}

// Channel is a channel the admin can choose as the Security Team channel.
// Private channels are the ones the app has been added to, which is all
// conversations.list can see.
type Channel struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Private bool   `json:"is_private"`
}

type channelsResponse struct {
	envelope
	Channels []Channel `json:"channels"`
}

// Channels lists the workspace's public channels and the private ones the app
// has been added to, following Slack's cursor pagination.
func (c *Client) Channels(ctx context.Context, token string) ([]Channel, error) {
	var all []Channel
	cursor := ""
	for range maxPages {
		q := url.Values{
			"types":            {"public_channel,private_channel"},
			"exclude_archived": {"true"},
			"limit":            {"200"},
		}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var resp channelsResponse
		if err := c.get(ctx, token, "conversations.list", q, &resp); err != nil {
			return nil, err
		}
		all = append(all, resp.Channels...)
		cursor = resp.ResponseMetadata.NextCursor
		if cursor == "" {
			return all, nil
		}
	}
	return nil, fmt.Errorf("%w: conversations.list did not stop paging", ErrUnavailable)
}

// Message is one chat.postMessage call. Blocks is raw Block Kit, rendered by
// the worker from a delivery's payload (ADR 0026).
type Message struct {
	Channel string
	Text    string
	Blocks  json.RawMessage
}

// PostMessage posts one message. Slack's ok false comes back as *APIError.
func (c *Client) PostMessage(ctx context.Context, token string, m Message) error {
	form := url.Values{
		"channel": {m.Channel},
		"text":    {m.Text},
	}
	if len(m.Blocks) > 0 {
		form.Set("blocks", string(m.Blocks))
	}
	var resp envelope
	return c.post(ctx, token, "chat.postMessage", form, &resp)
}

// envelope is the part every Web API answer shares.
type envelope struct {
	OK               bool   `json:"ok"`
	Error            string `json:"error"`
	ResponseMetadata struct {
		NextCursor string `json:"next_cursor"`
	} `json:"response_metadata"`
}

func (c *Client) get(ctx context.Context, token, method string, q url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/"+method+"?"+q.Encode(), nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return c.do(req, out)
}

func (c *Client) post(ctx context.Context, token, method string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/"+method, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("%w: read response: %v", ErrUnavailable, err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return &APIError{Code: "rate_limited", Status: resp.StatusCode}
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("%w: %s answered %d with %q", ErrUnavailable, req.URL.Path, resp.StatusCode, body)
	}
	if !env.OK {
		if env.Error == "" {
			env.Error = fmt.Sprintf("http_%d", resp.StatusCode)
		}
		return &APIError{Code: env.Error, Status: resp.StatusCode}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: decode %s: %v", ErrUnavailable, req.URL.Path, err)
	}
	return nil
}
