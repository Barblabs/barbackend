// Package cognito is the Amazon Cognito adapter: it verifies the access
// tokens Cognito issues and creates, disables and deletes users in the user pool
// (ADR 0013).
package cognito

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	firstFetchTimeout = 10 * time.Second
	// Cognito rotates its signing keys without notice, so a new key must be
	// picked up well before jwk's default of 30 days.
	keysMaxAge = time.Hour
)

type VerifierConfig struct {
	Issuer   string
	ClientID string
	JWKSURL  string
}

// Verifier checks Cognito access tokens against the user pool's signing keys,
// which it fetches once and then refreshes in the background until ctx ends.
type Verifier struct {
	keys    *jwk.Cache
	jwksURL string
	parse   []jwt.ParseOption
}

// NewVerifier fails when the signing keys cannot be fetched, so a wrong pool
// stops the server at start rather than rejecting every sign-in.
func NewVerifier(ctx context.Context, cfg VerifierConfig) (*Verifier, error) {
	keys, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		return nil, fmt.Errorf("start jwks cache: %w", err)
	}
	fetchCtx, cancel := context.WithTimeout(ctx, firstFetchTimeout)
	defer cancel()
	if err := keys.Register(fetchCtx, cfg.JWKSURL, jwk.WithMaxInterval(keysMaxAge)); err != nil {
		return nil, fmt.Errorf("fetch jwks %s: %w", cfg.JWKSURL, err)
	}
	return &Verifier{
		keys:    keys,
		jwksURL: cfg.JWKSURL,
		parse: []jwt.ParseOption{
			jwt.WithValidate(true),
			jwt.WithRequiredClaim(jwt.ExpirationKey),
			jwt.WithRequiredClaim(jwt.SubjectKey),
			jwt.WithIssuer(cfg.Issuer),
			// Cognito access tokens carry the app client in client_id, not aud,
			// and an ID token from the same pool must not pass for one.
			jwt.WithClaimValue("client_id", cfg.ClientID),
			jwt.WithClaimValue("token_use", "access"),
		},
	}, nil
}

// Verify returns the sub of a valid access token.
func (v *Verifier) Verify(ctx context.Context, token string) (string, error) {
	keys, err := v.keys.Lookup(ctx, v.jwksURL)
	if err != nil {
		return "", fmt.Errorf("signing keys: %w", err)
	}
	t, err := jwt.ParseString(token, append([]jwt.ParseOption{jwt.WithKeySet(keys)}, v.parse...)...)
	if err != nil {
		return "", err
	}
	sub, ok := t.Subject()
	if !ok || sub == "" {
		return "", errors.New("token has no sub")
	}
	return sub, nil
}
