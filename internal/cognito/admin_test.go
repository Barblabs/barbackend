package cognito_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"barbackend/internal/cognito"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// fakePool answers the Cognito JSON API for one user pool, which holds at
// most one user, as the tests need.
type fakePool struct {
	mu sync.Mutex
	// exists and passwordSet are the state of the user before the call.
	exists      bool
	passwordSet bool
	sub         string
	calls       []string
}

func (p *fakePool) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	action := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "AWSCognitoIdentityProviderService.")
	var in struct{ MessageAction string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if in.MessageAction != "" {
		action += ":" + in.MessageAction
	}
	p.calls = append(p.calls, action)
	attrs := []map[string]string{{"Name": "sub", "Value": p.sub}}
	switch action {
	case "AdminCreateUser":
		if p.exists {
			p.fail(w, "UsernameExistsException")
			return
		}
		p.exists = true
		p.reply(w, map[string]any{"User": map[string]any{"Attributes": attrs}})
	case "AdminCreateUser:RESEND":
		if p.passwordSet {
			p.fail(w, "UnsupportedUserStateException")
			return
		}
		p.reply(w, map[string]any{"User": map[string]any{"Attributes": attrs}})
	case "AdminGetUser":
		p.reply(w, map[string]any{"UserAttributes": attrs})
	default:
		http.Error(w, "unexpected "+action, http.StatusBadRequest)
	}
}

func (*fakePool) reply(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(body)
}

func (*fakePool) fail(w http.ResponseWriter, errType string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": errType, "message": errType})
}

func newAdmin(t *testing.T, pool *fakePool) *cognito.Admin {
	t.Helper()
	srv := httptest.NewServer(pool)
	t.Cleanup(srv.Close)
	return cognito.NewAdmin(aws.Config{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("key", "secret", ""),
		BaseEndpoint: aws.String(srv.URL),
	}, "pool")
}

func TestCreateUserCanBeRetried(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		exists      bool
		passwordSet bool
		wantCalls   []string
	}{
		{"new email", false, false, []string{"AdminCreateUser"}},
		{"invited before", true, false, []string{"AdminCreateUser", "AdminCreateUser:RESEND"}},
		{"password set", true, true, []string{"AdminCreateUser", "AdminCreateUser:RESEND", "AdminGetUser"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pool := &fakePool{exists: tt.exists, passwordSet: tt.passwordSet, sub: "the-sub"}

			sub, err := newAdmin(t, pool).CreateUser(t.Context(), "a@example.com")

			if err != nil || sub != "the-sub" || !slices.Equal(pool.calls, tt.wantCalls) {
				t.Errorf("sub = %q, err = %v, calls = %v, want the-sub after %v", sub, err, pool.calls, tt.wantCalls)
			}
		})
	}
}
