package claude_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"barbackend/internal/claude"
	"barbackend/internal/claude/claudetest"
)

func newClient(t *testing.T) (*claude.Client, *claudetest.Server) {
	t.Helper()
	srv := claudetest.New(t)
	return srv.Client(), srv
}

func TestStructuredSendsTheSchemaAndReturnsTheAnswer(t *testing.T) {
	c, srv := newClient(t)
	srv.Queue(claudetest.Text(`{"ok":true}`))
	schema := map[string]any{"type": "object"}

	raw, err := c.Structured(context.Background(), claude.Request{Model: "m", System: "instructions", Prompt: "data", Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"ok":true}` {
		t.Errorf("answer = %s", raw)
	}
	body := srv.Requests()[0]
	config := body["output_config"].(map[string]any)
	if config["effort"] != "medium" {
		t.Errorf("effort = %v", config["effort"])
	}
	format := config["format"].(map[string]any)
	if format["type"] != "json_schema" || format["schema"].(map[string]any)["type"] != "object" {
		t.Errorf("format = %v", format)
	}
	system := body["system"].([]any)[0].(map[string]any)["text"]
	if system != "instructions" {
		t.Errorf("system = %v", system)
	}
}

func TestStructuredSendsThePDFsBeforeThePrompt(t *testing.T) {
	c, srv := newClient(t)
	srv.Queue(claudetest.Text(`{}`))

	if _, err := c.Structured(context.Background(), claude.Request{Model: "m", Prompt: "data", PDFs: [][]byte{[]byte("%PDF-1.7"), []byte("%PDF-2.0")}}); err != nil {
		t.Fatal(err)
	}
	content := srv.Requests()[0]["messages"].([]any)[0].(map[string]any)["content"].([]any)
	if len(content) != 3 {
		t.Fatalf("content = %v, want two documents and a text", content)
	}
	for i, want := range []string{"JVBERi0xLjc=", "JVBERi0yLjA="} {
		document := content[i].(map[string]any)
		source, _ := document["source"].(map[string]any)
		if document["type"] != "document" || source["media_type"] != "application/pdf" || source["data"] != want {
			t.Errorf("document %d = %v, want the PDF in base64", i, document)
		}
	}
	if text := content[2].(map[string]any); text["type"] != "text" || text["text"] != "data" {
		t.Errorf("text = %v, want the prompt", text)
	}
}

func TestStructuredSendsTheCachedTextFirstMarkedForCaching(t *testing.T) {
	c, srv := newClient(t)
	srv.Queue(claudetest.Text(`{}`))

	if _, err := c.Structured(context.Background(), claude.Request{Model: "m", Cached: "catalog", Prompt: "data"}); err != nil {
		t.Fatal(err)
	}
	content := srv.Requests()[0]["messages"].([]any)[0].(map[string]any)["content"].([]any)
	if len(content) != 2 {
		t.Fatalf("content = %v, want the cached text and the prompt", content)
	}
	cached := content[0].(map[string]any)
	if cached["text"] != "catalog" || cached["cache_control"].(map[string]any)["type"] != "ephemeral" {
		t.Errorf("first block = %v, want the cached text with an ephemeral cache_control", cached)
	}
	if prompt := content[1].(map[string]any); prompt["text"] != "data" || prompt["cache_control"] != nil {
		t.Errorf("second block = %v, want the prompt, not cached", prompt)
	}
}

func TestStructuredFailures(t *testing.T) {
	tests := []struct {
		name  string
		reply claudetest.Reply
		want  error
	}{
		{"refused", claudetest.Refusal(), claude.ErrRefused},
		{"cut off", claudetest.Truncated(), claude.ErrIncomplete},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, srv := newClient(t)
			srv.Queue(tt.reply)
			if _, err := c.Structured(context.Background(), claude.Request{Model: "m"}); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestStructuredReportsAnAPIFailure(t *testing.T) {
	c, srv := newClient(t)
	srv.Queue(claudetest.Fail(http.StatusUnauthorized))
	if _, err := c.Structured(context.Background(), claude.Request{Model: "m"}); err == nil {
		t.Error("err = nil, want the API's failure")
	}
}

func TestConverseRunsToolsUntilTheModelAnswers(t *testing.T) {
	c, srv := newClient(t)
	srv.Queue(
		claudetest.ToolCall("call-1", "lookup", map[string]any{"key": "a"}),
		claudetest.ToolCall("call-2", "broken", map[string]any{}),
		claudetest.ToolCall("call-3", "invented", map[string]any{}),
		claudetest.Text("listo"),
	)
	var inputs []string
	tools := []claude.Tool{
		{Name: "lookup", Description: "d", Properties: map[string]any{"key": map[string]any{"type": "string"}}, Run: func(_ context.Context, in json.RawMessage) (string, error) {
			inputs = append(inputs, string(in))
			return "value", nil
		}},
		{Name: "broken", Description: "d", Properties: map[string]any{}, Run: func(context.Context, json.RawMessage) (string, error) {
			return "", errors.New("it broke")
		}},
	}

	reply, err := c.Converse(context.Background(), claude.Turn{Model: "m", System: "s", Tools: tools, Message: "hola"})
	if err != nil {
		t.Fatal(err)
	}
	if reply.Text != "listo" {
		t.Errorf("text = %q", reply.Text)
	}
	if len(inputs) != 1 || !strings.Contains(inputs[0], `"key":"a"`) {
		t.Errorf("inputs = %v", inputs)
	}
	requests := srv.Requests()
	if len(requests) != 4 {
		t.Fatalf("requests = %d, want 4", len(requests))
	}
	results := []struct {
		text    string
		isError bool
	}{{"value", false}, {"it broke", true}, {"invented", true}}
	for i, want := range results {
		result := lastBlock(requests[i+1])
		if result["type"] != "tool_result" || result["is_error"] != want.isError || !strings.Contains(mustJSON(t, result), want.text) {
			t.Errorf("result %d = %v, want %+v", i, result, want)
		}
	}
	tool := requests[0]["tools"].([]any)[0].(map[string]any)
	schema := tool["input_schema"].(map[string]any)
	if tool["strict"] != true || schema["additionalProperties"] != false || schema["required"].([]any)[0] != "key" {
		t.Errorf("tool = %v", tool)
	}
	if requests[0]["fallbacks"] != "default" {
		t.Errorf("fallbacks = %v", requests[0]["fallbacks"])
	}
}

func TestConverseMakesTheModelAnswerAfterTooManyRounds(t *testing.T) {
	c, srv := newClient(t)
	for range 7 {
		srv.Queue(claudetest.ToolCall("call", "lookup", map[string]any{}))
	}
	srv.Queue(claudetest.Text("con lo que tengo"))
	tools := []claude.Tool{{Name: "lookup", Description: "d", Properties: map[string]any{}, Run: func(context.Context, json.RawMessage) (string, error) {
		return "value", nil
	}}}

	reply, err := c.Converse(context.Background(), claude.Turn{Model: "m", Tools: tools, Message: "hola"})
	if err != nil {
		t.Fatal(err)
	}
	if reply.Text != "con lo que tengo" {
		t.Errorf("text = %q", reply.Text)
	}
	requests := srv.Requests()
	if len(requests) != 8 {
		t.Fatalf("requests = %d, want 8", len(requests))
	}
	if choice := requests[7]["tool_choice"].(map[string]any); choice["type"] != "none" {
		t.Errorf("last tool_choice = %v", choice)
	}
	if _, ok := requests[6]["tool_choice"]; ok {
		t.Errorf("earlier round was forced: %v", requests[6]["tool_choice"])
	}
}

func TestConverseContinuesFromTheHistoryWithTheModelsReasoning(t *testing.T) {
	c, srv := newClient(t)
	srv.Queue(claudetest.Text("primera"), claudetest.Text("segunda"))

	first, err := c.Converse(context.Background(), claude.Turn{Model: "m", Message: "uno"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Converse(context.Background(), claude.Turn{Model: "m", History: first.History, Message: "dos"}); err != nil {
		t.Fatal(err)
	}

	messages := srv.Requests()[1]["messages"].([]any)
	if len(messages) != 3 {
		t.Fatalf("messages = %d, want user, assistant, user", len(messages))
	}
	assistant := messages[1].(map[string]any)["content"].([]any)
	thinking := assistant[0].(map[string]any)
	if thinking["type"] != "thinking" || thinking["signature"] != "signature" {
		t.Errorf("first assistant block = %v, want the thinking block kept", thinking)
	}
}

func TestConverseFailsWhenTheModelIgnoresTheLastRound(t *testing.T) {
	c, srv := newClient(t)
	for range 8 {
		srv.Queue(claudetest.ToolCall("call", "lookup", map[string]any{}))
	}
	tools := []claude.Tool{{Name: "lookup", Description: "d", Properties: map[string]any{}, Run: func(context.Context, json.RawMessage) (string, error) {
		return "value", nil
	}}}

	_, err := c.Converse(context.Background(), claude.Turn{Model: "m", Tools: tools, Message: "hola"})

	if !errors.Is(err, claude.ErrIncomplete) {
		t.Errorf("err = %v, want ErrIncomplete", err)
	}
	if len(srv.Requests()) != 8 {
		t.Errorf("requests = %d, want the rounds to be bounded", len(srv.Requests()))
	}
}

func TestConverseKeepsWhatTheAPISentThatTheSDKDoesNotKnow(t *testing.T) {
	c, srv := newClient(t)
	srv.Queue(claudetest.Text("primera"), claudetest.Text("segunda"))

	first, err := c.Converse(context.Background(), claude.Turn{Model: "m", Message: "uno"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(first.History), claudetest.UnknownField) {
		t.Errorf("history = %s, want it as the API sent it", first.History)
	}
	if _, err := c.Converse(context.Background(), claude.Turn{Model: "m", History: first.History, Message: "dos"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mustJSON(t, srv.Requests()[1]["messages"]), claudetest.UnknownField) {
		t.Error("the replay lost a field the SDK does not know")
	}
}

func TestConverseReplaysToolCallsAsTheyCame(t *testing.T) {
	c, srv := newClient(t)
	srv.Queue(claudetest.ToolCall("call-1", "lookup", map[string]any{"key": "a"}), claudetest.Text("primera"), claudetest.Text("segunda"))
	tools := []claude.Tool{{Name: "lookup", Description: "d", Properties: map[string]any{}, Run: func(context.Context, json.RawMessage) (string, error) {
		return "value", nil
	}}}

	first, err := c.Converse(context.Background(), claude.Turn{Model: "m", Tools: tools, Message: "uno"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Converse(context.Background(), claude.Turn{Model: "m", Tools: tools, History: first.History, Message: "dos"}); err != nil {
		t.Fatal(err)
	}

	messages := srv.Requests()[2]["messages"].([]any)
	if len(messages) != 5 {
		t.Fatalf("messages = %d, want user, tool call, tool result, answer, user", len(messages))
	}
	call := messages[1].(map[string]any)["content"].([]any)[1].(map[string]any)
	if call["type"] != "tool_use" || call["id"] != "call-1" || call["input"].(map[string]any)["key"] != "a" {
		t.Errorf("replayed call = %v", call)
	}
	result := messages[2].(map[string]any)["content"].([]any)[0].(map[string]any)
	if result["type"] != "tool_result" || result["tool_use_id"] != "call-1" {
		t.Errorf("replayed result = %v", result)
	}
}

func TestConverseRejectsAHistoryThatIsNotAList(t *testing.T) {
	c, srv := newClient(t)
	_, err := c.Converse(context.Background(), claude.Turn{Model: "m", History: json.RawMessage(`{"not":"a list"}`), Message: "hola"})
	if !errors.Is(err, claude.ErrInvalidHistory) {
		t.Errorf("err = %v, want ErrInvalidHistory", err)
	}
	if len(srv.Requests()) != 0 {
		t.Error("the model was called")
	}
}

func TestConverseFailures(t *testing.T) {
	tests := []struct {
		name  string
		reply claudetest.Reply
		want  error
	}{
		{"refused", claudetest.Refusal(), claude.ErrRefused},
		{"cut off", claudetest.Truncated(), claude.ErrIncomplete},
		{"no text", claudetest.Empty(), claude.ErrIncomplete},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, srv := newClient(t)
			srv.Queue(tt.reply)
			if _, err := c.Converse(context.Background(), claude.Turn{Model: "m", Message: "hola"}); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func lastBlock(r claudetest.Request) map[string]any {
	messages := r["messages"].([]any)
	content := messages[len(messages)-1].(map[string]any)["content"].([]any)
	return content[len(content)-1].(map[string]any)
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
