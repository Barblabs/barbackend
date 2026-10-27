// Package cognitotest stands in for a Cognito user pool in tests: it serves
// a JWKS over httptest and signs access tokens with its key, so the real
// cognito.Verifier checks them without calling AWS.
package cognitotest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"barbackend/internal/cognito"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	Issuer   = "https://cognito-idp.test/pool"
	ClientID = "test-client"
	keyID    = "test-key"
)

type Pool struct {
	Config cognito.VerifierConfig
	key    jwk.Key
}

func New(t *testing.T) *Pool {
	t.Helper()
	key := newKey(t)
	public, err := jwk.PublicKeyOf(key)
	if err != nil {
		t.Fatal(err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(public); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return &Pool{Config: cognito.VerifierConfig{Issuer: Issuer, ClientID: ClientID, JWKSURL: srv.URL}, key: key}
}

func (p *Pool) Verifier(t *testing.T) *cognito.Verifier {
	t.Helper()
	v, err := cognito.NewVerifier(t.Context(), p.Config)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Claims are those of a valid access token for sub, for a test to break.
func Claims(sub string) map[string]any {
	return map[string]any{
		"sub":       sub,
		"iss":       Issuer,
		"client_id": ClientID,
		"token_use": "access",
		"exp":       time.Now().Add(time.Hour),
	}
}

func (p *Pool) AccessToken(t *testing.T, sub string) string {
	t.Helper()
	return p.Sign(t, Claims(sub))
}

func (p *Pool) Sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	return sign(t, p.key, claims)
}

// SignWithOtherKey signs with a key of the same id that the pool does not
// publish, as a forger would.
func SignWithOtherKey(t *testing.T, claims map[string]any) string {
	t.Helper()
	return sign(t, newKey(t), claims)
}

func newKey(t *testing.T) jwk.Key {
	t.Helper()
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.Import(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		t.Fatal(err)
	}
	return key
}

func sign(t *testing.T, key jwk.Key, claims map[string]any) string {
	t.Helper()
	token := jwt.New()
	for name, v := range claims {
		if err := token.Set(name, v); err != nil {
			t.Fatal(err)
		}
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}
