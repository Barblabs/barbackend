package slack

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"barbackend/internal/encryption"
	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

const (
	// TestMessage is what the Connect Slack page posts to prove the
	// installation works. It does not touch the delivery queue.
	TestMessage = "barbattack is connected. Findings will be posted to this channel."

	stateOwner    = "slack oauth state"
	stateLifetime = 10 * time.Minute
)

var (
	// ErrInvalidState is a state that was tampered with, sealed with another
	// key, or has expired.
	ErrInvalidState = errors.New("invalid slack oauth state")
	// ErrNotInstalled is a Customer with no Slack installation, or one that
	// was disconnected.
	ErrNotInstalled = errors.New("slack is not installed")
	// ErrNeedsReauthorisation is an installation Slack revoked: the admin
	// reinstalls before it can send again.
	ErrNeedsReauthorisation = errors.New("slack needs re-authorisation")
	// ErrNoChannel is a test message before an admin picks the Security Team
	// channel.
	ErrNoChannel = errors.New("no security team channel is set")
	// ErrInvalidChannel is a channel with no id.
	ErrInvalidChannel = errors.New("invalid slack channel")
)

// State is the lifecycle of an installation (ADR 0025). It is stored as the
// plain text the database column holds.
type State string

const (
	Active               State = "active"
	NeedsReauthorisation State = "needs re-authorisation"
	Removed              State = "removed"
)

// Installation is a Customer's Slack connection as a person sees it. It
// holds no token.
type Installation struct {
	TeamID      string
	TeamName    string
	ChannelID   string
	ChannelName string
	State       State
}

// TestResult is Slack's answer to the test message. A refusal is a result,
// not an error, so the admin sees Slack's code.
type TestResult struct {
	OK    bool
	Error string
}

// Service connects a Customer's Slack workspace and sends what the pipeline
// queues (ADR 0025). It seals the bot token with key, so only this package
// ever sees it decrypted (ADR 0012).
type Service struct {
	db       *postgres.DB
	client   *Client
	key      encryption.Key
	now      func() time.Time
	lifetime time.Duration
}

func New(db *postgres.DB, client *Client, key encryption.Key) *Service {
	return &Service{db: db, client: client, key: key, now: time.Now, lifetime: stateLifetime}
}

// StartInstall returns the authorize URL for the portal's popup. The Customer
// comes from the signed-in admin, never from the request (ADR 0013).
func (s *Service) StartInstall(_ context.Context, caller tenancy.User) (string, error) {
	customer, err := caller.ManageUsers()
	if err != nil {
		return "", err
	}
	state, err := s.sealState(customer)
	if err != nil {
		return "", err
	}
	return s.client.AuthorizeURL(state), nil
}

// HandleCallback exchanges the code for a bot token and stores the
// installation. It is the one Slack operation with no signed-in caller: the
// sealed state says which Customer is installing.
func (s *Service) HandleCallback(ctx context.Context, code, state string) error {
	customer, err := s.openState(state)
	if err != nil {
		return err
	}
	if code == "" {
		return fmt.Errorf("%w: no code", ErrOAuth)
	}
	oauth, err := s.client.Exchange(ctx, code)
	if err != nil {
		return err
	}
	sealed, err := s.key.Seal([]byte(oauth.AccessToken), owner(customer))
	if err != nil {
		return fmt.Errorf("seal slack token of customer %s: %w", customer, err)
	}
	return s.db.InTx(ctx, func(tx *postgres.Tx) error {
		return tx.SaveSlackInstallation(ctx, customer, oauth.TeamID, oauth.TeamName, sealed)
	})
}

// Status is the Customer's installation, or nil when it has none or has
// disconnected. Every role of the Customer may read it.
func (s *Service) Status(ctx context.Context, caller tenancy.User) (*Installation, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return nil, err
	}
	stored, err := s.stored(ctx, customer)
	if errors.Is(err, postgres.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if State(stored.State) == Removed {
		return nil, nil
	}
	return installation(stored), nil
}

// Channels lists the workspace's channels for the Security Team picker. Every
// role of the Customer may read it.
func (s *Service) Channels(ctx context.Context, caller tenancy.User) ([]Channel, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return nil, err
	}
	token, err := s.token(ctx, customer)
	if err != nil {
		return nil, err
	}
	return s.client.Channels(ctx, token)
}

// SetChannel stores the Security Team channel the admin picked.
func (s *Service) SetChannel(ctx context.Context, caller tenancy.User, channelID, channelName string) (*Installation, error) {
	customer, err := caller.ManageUsers()
	if err != nil {
		return nil, err
	}
	channelID = strings.TrimSpace(channelID)
	channelName = strings.TrimSpace(channelName)
	if channelID == "" || channelName == "" {
		return nil, ErrInvalidChannel
	}
	err = s.db.InTx(ctx, func(tx *postgres.Tx) error {
		return tx.SetSlackChannel(ctx, customer, channelID, channelName)
	})
	if errors.Is(err, postgres.ErrNotFound) {
		return nil, ErrNotInstalled
	}
	if err != nil {
		return nil, err
	}
	return s.Status(ctx, caller)
}

// SendTest posts a fixed message to the Security Team channel, synchronously,
// so the admin sees whether the connection works right now. It does not touch
// the delivery queue.
func (s *Service) SendTest(ctx context.Context, caller tenancy.User) (TestResult, error) {
	customer, err := caller.ManageUsers()
	if err != nil {
		return TestResult{}, err
	}
	stored, err := s.stored(ctx, customer)
	if errors.Is(err, postgres.ErrNotFound) {
		return TestResult{}, ErrNotInstalled
	}
	if err != nil {
		return TestResult{}, err
	}
	switch State(stored.State) {
	case Removed:
		return TestResult{}, ErrNotInstalled
	case NeedsReauthorisation:
		return TestResult{}, ErrNeedsReauthorisation
	}
	if stored.ChannelID == "" {
		return TestResult{}, ErrNoChannel
	}
	token, err := s.token(ctx, customer)
	if err != nil {
		return TestResult{}, err
	}
	err = s.client.PostMessage(ctx, token, Message{Channel: stored.ChannelID, Text: TestMessage})
	var api *APIError
	if errors.As(err, &api) {
		if api.Code == "invalid_auth" || api.Code == "token_revoked" {
			s.needsReauthorisation(ctx, customer)
		}
		return TestResult{OK: false, Error: api.Code}, nil
	}
	if err != nil {
		return TestResult{}, err
	}
	return TestResult{OK: true}, nil
}

// Disconnect removes the installation from the Customer's view and drops its
// token. A later install returns it to active. It is idempotent.
func (s *Service) Disconnect(ctx context.Context, caller tenancy.User) error {
	customer, err := caller.ManageUsers()
	if err != nil {
		return err
	}
	return s.db.InTx(ctx, func(tx *postgres.Tx) error {
		return tx.RemoveSlackInstallation(ctx, customer)
	})
}

// needsReauthorisation flips the installation after Slack revoked the token
// (ADR 0025). A failure to record it is not worth hiding the send's result.
func (s *Service) needsReauthorisation(ctx context.Context, customer tenancy.CustomerID) {
	_ = s.db.InTx(ctx, func(tx *postgres.Tx) error {
		return tx.SetSlackState(ctx, customer, string(NeedsReauthorisation))
	})
}

func (s *Service) stored(ctx context.Context, customer tenancy.CustomerID) (postgres.StoredSlackInstallation, error) {
	return postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) (postgres.StoredSlackInstallation, error) {
		return tx.SlackInstallation(ctx, customer)
	})
}

// token is the decrypted bot token of an installation that can send.
func (s *Service) token(ctx context.Context, customer tenancy.CustomerID) (string, error) {
	stored, err := s.stored(ctx, customer)
	if errors.Is(err, postgres.ErrNotFound) {
		return "", ErrNotInstalled
	}
	if err != nil {
		return "", err
	}
	switch State(stored.State) {
	case Removed:
		return "", ErrNotInstalled
	case NeedsReauthorisation:
		return "", ErrNeedsReauthorisation
	}
	if stored.BotToken == nil {
		return "", ErrNotInstalled
	}
	token, err := s.key.Open(stored.BotToken, owner(customer))
	if err != nil {
		return "", fmt.Errorf("open slack token of customer %s: %w", customer, err)
	}
	return string(token), nil
}

func installation(stored postgres.StoredSlackInstallation) *Installation {
	return &Installation{
		TeamID:      stored.TeamID,
		TeamName:    stored.TeamName,
		ChannelID:   stored.ChannelID,
		ChannelName: stored.ChannelName,
		State:       State(stored.State),
	}
}

type installState struct {
	Customer string    `json:"customer"`
	Expires  time.Time `json:"expires"`
}

func (s *Service) sealState(customer tenancy.CustomerID) (string, error) {
	raw, err := json.Marshal(installState{Customer: customer.String(), Expires: s.now().Add(s.lifetime)})
	if err != nil {
		return "", fmt.Errorf("encode slack state: %w", err)
	}
	sealed, err := s.key.Seal(raw, []byte(stateOwner))
	if err != nil {
		return "", fmt.Errorf("seal slack state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *Service) openState(state string) (tenancy.CustomerID, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return tenancy.CustomerID{}, fmt.Errorf("%w: not base64", ErrInvalidState)
	}
	raw, err := s.key.Open(sealed, []byte(stateOwner))
	if err != nil {
		return tenancy.CustomerID{}, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	var payload installState
	if err := json.Unmarshal(raw, &payload); err != nil {
		return tenancy.CustomerID{}, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	id, err := uuid.Parse(payload.Customer)
	if err != nil || id == uuid.Nil {
		return tenancy.CustomerID{}, fmt.Errorf("%w: customer %q", ErrInvalidState, payload.Customer)
	}
	if !s.now().Before(payload.Expires) {
		return tenancy.CustomerID{}, fmt.Errorf("%w: expired", ErrInvalidState)
	}
	return tenancy.CustomerID(id), nil
}

func owner(customer tenancy.CustomerID) []byte {
	return []byte(customer.String())
}
