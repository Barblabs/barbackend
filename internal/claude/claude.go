// Package claude is the adapter over Anthropic's Messages API (ADR 0016).
package claude

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
)

const (
	maxTokens = 16000
	maxRounds = 8
)

var (
	// ErrRefused is a request the model's safety classifiers declined.
	ErrRefused = errors.New("model refused the request")
	// ErrIncomplete is a response cut off before the model finished.
	ErrIncomplete = errors.New("model response is incomplete")
	// ErrInvalidHistory is a Turn's History that is not a list of messages.
	ErrInvalidHistory = errors.New("conversation history is invalid")
)

// Client finds its credentials as the SDK does, such as in ANTHROPIC_API_KEY.
// Calling without any fails with the SDK's error naming what it tried.
type Client struct {
	api anthropic.Client
}

// New returns a Client of the API at baseURL, or of the SDK's default when it
// is empty.
func New(baseURL string) *Client {
	var options []option.RequestOption
	if baseURL != "" {
		options = append(options, option.WithBaseURL(baseURL))
	}
	return &Client{api: anthropic.NewClient(options...)}
}

// Request asks a model for one JSON document.
type Request struct {
	Model  string
	System string
	Prompt string
	// Cached is text the model reads first, before PDFs and Prompt, that many
	// requests share, such as a catalog: the API caches it with the system
	// prompt, so a later request reads it at a tenth of the input price.
	Cached string
	// PDFs are PDF documents the model reads, in order, before Prompt.
	PDFs [][]byte
	// Schema is the JSON Schema of the answer, which the API enforces.
	Schema map[string]any
}

// Structured returns the JSON document the model answered with. It fails with
// ErrRefused or ErrIncomplete when there is none.
func (c *Client) Structured(ctx context.Context, r Request) ([]byte, error) {
	msg, err := c.api.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     r.Model,
		MaxTokens: maxTokens,
		System:    []anthropic.TextBlockParam{{Text: r.System}},
		Messages:  []anthropic.MessageParam{anthropic.NewUserMessage(r.content()...)},
		OutputConfig: anthropic.OutputConfigParam{
			Effort: anthropic.OutputConfigEffortMedium,
			Format: anthropic.JSONOutputFormatParam{Schema: r.Schema},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("call %s: %w", r.Model, err)
	}
	if err := stopError(r.Model, string(msg.StopReason)); err != nil {
		return nil, err
	}
	var text strings.Builder
	for _, block := range msg.Content {
		if t, ok := block.AsAny().(anthropic.TextBlock); ok {
			text.WriteString(t.Text)
		}
	}
	return []byte(text.String()), nil
}

// The API reads a document best placed before the text about it.
func (r Request) content() []anthropic.ContentBlockParamUnion {
	blocks := make([]anthropic.ContentBlockParamUnion, 0, len(r.PDFs)+2)
	if r.Cached != "" {
		blocks = append(blocks, anthropic.ContentBlockParamUnion{OfText: &anthropic.TextBlockParam{
			Text: r.Cached, CacheControl: anthropic.NewCacheControlEphemeralParam(),
		}})
	}
	for _, pdf := range r.PDFs {
		blocks = append(blocks, anthropic.NewDocumentBlock(anthropic.Base64PDFSourceParam{Data: base64.StdEncoding.EncodeToString(pdf)}))
	}
	return append(blocks, anthropic.NewTextBlock(r.Prompt))
}

// Tool is a function a model may call during Converse.
type Tool struct {
	Name        string
	Description string
	// Properties are the JSON Schema of the tool's input, all of them required
	// by the API's strict mode: an optional one allows null instead.
	Properties map[string]any
	// Run's error text reaches the model, which can recover from it.
	Run func(ctx context.Context, input json.RawMessage) (string, error)
}

// Turn is one message of a person to a model.
type Turn struct {
	Model   string
	System  string
	Tools   []Tool
	History json.RawMessage
	Message string
}

// Reply is the model's answer to a Turn.
type Reply struct {
	Text string
	// History is the conversation so far, for the next Turn. Send it back
	// unedited: the API rejects a history whose earlier turns changed.
	History json.RawMessage
}

// Converse sends the message after the History and runs the tools the model
// calls, up to the last round, in which it can only answer. It fails with
// ErrInvalidHistory, ErrRefused or ErrIncomplete, which includes a turn that
// ends without text: the API rejects a replayed message with empty content.
//
// The history goes to the API through WithJSONSet, not the SDK's types,
// because the API requires replayed thinking blocks unchanged and a round trip
// through those types can alter them.
func (c *Client) Converse(ctx context.Context, t Turn) (Reply, error) {
	history, err := newHistory(t.History, t.Message)
	if err != nil {
		return Reply{}, err
	}
	params := anthropic.BetaMessageNewParams{
		Model:        t.Model,
		MaxTokens:    maxTokens,
		System:       []anthropic.BetaTextBlockParam{{Text: t.System}},
		Tools:        toolParams(t.Tools),
		OutputConfig: anthropic.BetaOutputConfigParam{Effort: anthropic.BetaOutputConfigEffortMedium},
		CacheControl: anthropic.NewBetaCacheControlEphemeralParam(),
		Fallbacks:    anthropic.BetaFallbacksParamOfDefault(),
		Betas:        []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01},
	}
	for round := range maxRounds {
		if round == maxRounds-1 {
			params.ToolChoice = anthropic.BetaToolChoiceUnionParam{OfNone: &anthropic.BetaToolChoiceNoneParam{}}
		}
		msg, err := c.api.Beta.Messages.New(ctx, params, option.WithJSONSet("messages", history))
		if err != nil {
			return Reply{}, fmt.Errorf("call %s: %w", t.Model, err)
		}
		if err := stopError(t.Model, string(msg.StopReason)); err != nil {
			return Reply{}, err
		}
		history = append(history, assistantMessage(msg))
		if msg.StopReason != anthropic.BetaStopReasonToolUse {
			return newReply(msg, history)
		}
		results, err := runTools(ctx, t.Tools, msg)
		if err != nil {
			return Reply{}, err
		}
		history = append(history, results)
	}
	return Reply{}, fmt.Errorf("%s kept calling tools: %w", t.Model, ErrIncomplete)
}

func newHistory(stored json.RawMessage, message string) ([]json.RawMessage, error) {
	var history []json.RawMessage
	if len(stored) > 0 {
		if err := json.Unmarshal(stored, &history); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidHistory, err)
		}
	}
	raw, err := userMessage(anthropic.NewBetaTextBlock(message))
	if err != nil {
		return nil, err
	}
	return append(history, raw), nil
}

func userMessage(blocks ...anthropic.BetaContentBlockParamUnion) (json.RawMessage, error) {
	raw, err := json.Marshal(anthropic.NewBetaUserMessage(blocks...))
	if err != nil {
		return nil, fmt.Errorf("write message: %w", err)
	}
	return raw, nil
}

func assistantMessage(msg *anthropic.BetaMessage) json.RawMessage {
	return json.RawMessage(`{"role":"assistant","content":` + msg.JSON.Content.Raw() + `}`)
}

func toolParams(tools []Tool) []anthropic.BetaToolUnionParam {
	params := make([]anthropic.BetaToolUnionParam, len(tools))
	for i, tool := range tools {
		params[i] = anthropic.BetaToolUnionParam{OfTool: &anthropic.BetaToolParam{
			Name:        tool.Name,
			Description: anthropic.String(tool.Description),
			Strict:      anthropic.Bool(true),
			InputSchema: anthropic.BetaToolInputSchemaParam{
				Properties:  tool.Properties,
				Required:    slices.Sorted(maps.Keys(tool.Properties)),
				ExtraFields: map[string]any{"additionalProperties": false},
			},
		}}
	}
	return params
}

func runTools(ctx context.Context, tools []Tool, msg *anthropic.BetaMessage) (json.RawMessage, error) {
	var results []anthropic.BetaContentBlockParamUnion
	for _, block := range msg.Content {
		use, ok := block.AsAny().(anthropic.BetaToolUseBlock)
		if !ok {
			continue
		}
		out, err := run(ctx, tools, use)
		if err != nil {
			out = err.Error()
		}
		results = append(results, anthropic.NewBetaToolResultBlock(use.ID, out, err != nil))
	}
	return userMessage(results...)
}

func run(ctx context.Context, tools []Tool, use anthropic.BetaToolUseBlock) (string, error) {
	i := slices.IndexFunc(tools, func(t Tool) bool { return t.Name == use.Name })
	if i < 0 {
		return "", fmt.Errorf("unknown tool %q", use.Name)
	}
	return tools[i].Run(ctx, json.RawMessage(use.JSON.Input.Raw()))
}

func newReply(msg *anthropic.BetaMessage, history []json.RawMessage) (Reply, error) {
	var text strings.Builder
	for _, block := range msg.Content {
		if t, ok := block.AsAny().(anthropic.BetaTextBlock); ok {
			text.WriteString(t.Text)
		}
	}
	if strings.TrimSpace(text.String()) == "" {
		return Reply{}, fmt.Errorf("%s answered without text: %w", msg.Model, ErrIncomplete)
	}
	raw, err := json.Marshal(history)
	if err != nil {
		return Reply{}, fmt.Errorf("write history: %w", err)
	}
	return Reply{Text: text.String(), History: raw}, nil
}

func stopError(model, reason string) error {
	switch reason {
	case "end_turn", "stop_sequence", "tool_use":
		return nil
	case "refusal":
		return fmt.Errorf("%s: %w", model, ErrRefused)
	default:
		return fmt.Errorf("%s stopped with %s: %w", model, reason, ErrIncomplete)
	}
}
