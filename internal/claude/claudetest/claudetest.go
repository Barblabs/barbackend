// Package claudetest stands in for Anthropic's Messages API in tests: it
// answers with the replies a test queues and records every request, so the
// real claude.Client runs without calling Anthropic.
package claudetest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// UnknownField is on every message's thinking block and in no SDK type, so a
// test can tell a history kept as the API sent it from one rebuilt from them.
const UnknownField = "future_field"

// Server answers each request with the next queued Reply.
type Server struct {
	URL string

	mu       sync.Mutex
	replies  []Reply
	requests []Request
	held     chan struct{}
}

// Reply is one answer of the API.
type Reply struct {
	status int
	body   map[string]any
}

// Request is the JSON body of a request to the API.
type Request map[string]any

// New returns a Server that a test closes on cleanup.
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{}
	srv := httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(srv.Close)
	s.URL = srv.URL
	return s
}

// Queue adds replies, in order, after those already queued.
func (s *Server) Queue(replies ...Reply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replies = append(s.replies, replies...)
}

// Hold keeps every request waiting for its reply until release is called.
func (s *Server) Hold() (release func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	held := make(chan struct{})
	s.held = held
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.held = nil
		close(held)
	}
}

// Requests are those received so far, in order.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var request Request
	_ = json.Unmarshal(raw, &request)

	s.mu.Lock()
	s.requests = append(s.requests, request)
	reply := Fail(http.StatusBadRequest)
	if len(s.replies) > 0 {
		reply, s.replies = s.replies[0], s.replies[1:]
	}
	held := s.held
	s.mu.Unlock()

	if held != nil {
		<-held
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(reply.status)
	_ = json.NewEncoder(w).Encode(reply.body)
}

// Text is a message ending the turn with text.
func Text(text string) Reply {
	return message("end_turn", textBlock(text))
}

// JSON is a message ending the turn with v as structured output.
func JSON(t *testing.T, v any) Reply {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return Text(string(raw))
}

// ToolCall is a message calling one tool.
func ToolCall(id, name string, input map[string]any) Reply {
	return message("tool_use", map[string]any{"type": "tool_use", "id": id, "name": name, "input": input})
}

// Refusal is a request the safety classifiers declined.
func Refusal() Reply {
	return message("refusal")
}

// Empty is a message ending the turn with no content but its thinking.
func Empty() Reply {
	return message("end_turn")
}

// Truncated is a message cut off by max_tokens.
func Truncated() Reply {
	return message("max_tokens", textBlock("{"))
}

// Fail is an API error that the SDK does not retry.
func Fail(status int) Reply {
	return Reply{status: status, body: map[string]any{
		"type":  "error",
		"error": map[string]any{"type": "invalid_request_error", "message": "claudetest failure"},
	}}
}

func textBlock(text string) map[string]any {
	return map[string]any{"type": "text", "text": text}
}

func message(stop string, blocks ...map[string]any) Reply {
	content := []map[string]any{{"type": "thinking", "thinking": "", "signature": "signature", UnknownField: "kept"}}
	content = append(content, blocks...)
	return Reply{status: http.StatusOK, body: map[string]any{
		"id":          "msg_test",
		"type":        "message",
		"role":        "assistant",
		"model":       "claudetest",
		"content":     content,
		"stop_reason": stop,
		"usage":       map[string]any{"input_tokens": 1, "output_tokens": 1},
	}}
}
