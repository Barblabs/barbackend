package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"barbackend/internal/agents"
	"barbackend/internal/business"
	"barbackend/internal/businesscontext"
	"barbackend/internal/tenancy"
	"github.com/danielgtaylor/huma/v2"
)

const (
	// Documents grow by a third in base64.
	maxDraftBodyBytes = agents.MaxDocumentsBytes*4/3 + 1<<20
	draftBodyTimeout  = time.Minute
)

type businessContextHandler struct {
	contexts *businesscontext.Service
	agents   *agents.Service
}

func (h businessContextHandler) register(api huma.API) {
	register(api, huma.Operation{
		OperationID: "get-business-context",
		Method:      http.MethodGet,
		Path:        "/business-context",
		Summary:     "Get the newest version of the Customer's Business Context",
		Description: "Version 0, with nothing stated, until a Customer Admin saves one. Every User of the Customer reads it.",
	}, h.get)
	register(api, huma.Operation{
		OperationID: "save-business-context",
		Method:      http.MethodPut,
		Path:        "/business-context",
		Summary:     "Save the Customer's Business Context as its next version",
		Description: "Only a Customer Admin saves. version is the one read: a save on any other is refused with business_context_stale, so a concurrent save is never overwritten.",
		Errors:      []int{http.StatusBadRequest, http.StatusConflict},
	}, h.save)
	register(api, huma.Operation{
		OperationID: "get-business-context-brief",
		Method:      http.MethodGet,
		Path:        "/business-context/brief",
		Summary:     "Read the Customer's Business Context as Markdown, for a model's prompt or a person",
		Description: "Every field has a line, and one not stated says so. The ETag is the version.",
		Responses: map[string]*huma.Response{
			"200": {
				Content: map[string]*huma.MediaType{"text/markdown": {Schema: &huma.Schema{Type: huma.TypeString}}},
				Headers: map[string]*huma.Param{"ETag": {Schema: &huma.Schema{Type: huma.TypeString}}},
			},
		},
	}, h.brief)
	register(api, huma.Operation{
		OperationID:     "draft-business-context",
		Method:          http.MethodPost,
		Path:            "/business-context/draft",
		Summary:         "Ask the Drafter for a Business Context read from documents, without saving it",
		Description:     "Only a Customer Admin asks. Give pasted text, files or both: text, Markdown, CSV, JSON, PDFs or Word documents (.docx), up to 10 of them, 10 MB each and 20 MB together. The Drafter reads them together, which can take a minute. The draft is for a Customer Admin to review and save.",
		MaxBodyBytes:    maxDraftBodyBytes,
		BodyReadTimeout: draftBodyTimeout,
		Errors:          []int{http.StatusBadRequest, http.StatusBadGateway},
	}, h.draft)
}

type businessContextResponse struct {
	Version   int                   `json:"version" doc:"0 until the Customer saves one; a save sends back the version it read"`
	SavedAt   *time.Time            `json:"saved_at"`
	SavedBy   *string               `json:"saved_by" doc:"The email of the User who saved it"`
	Context   businessContextFields `json:"context"`
	KeyFields []string              `json:"key_fields" doc:"The paths of what the Agents need most, such as profile.sectors"`
	Gaps      []string              `json:"gaps" doc:"The key fields not stated"`
}

type saveBusinessContextRequest struct {
	_       struct{}              `additionalProperties:"true"`
	Version int                   `json:"version" minimum:"0" doc:"The version read, which this save follows"`
	Context businessContextFields `json:"context"`
}

type draftBusinessContextRequest struct {
	_     struct{}    `additionalProperties:"true"`
	Text  string      `json:"text,omitempty" doc:"Pasted text, read as one more document"`
	Files []draftFile `json:"files,omitempty"`
}

type draftFile struct {
	_         struct{} `additionalProperties:"true"`
	Name      string   `json:"name" minLength:"1"`
	MediaType string   `json:"media_type" minLength:"1" doc:"Such as text/plain, application/pdf or application/vnd.openxmlformats-officedocument.wordprocessingml.document"`
	Data      []byte   `json:"data" doc:"The file's bytes"`
}

type draftResponse struct {
	Context businessContextFields `json:"context"`
	Gaps    []string              `json:"gaps" doc:"The key fields the document did not state"`
}

type briefOutput struct {
	ContentType string `header:"Content-Type"`
	ETag        string `header:"ETag"`
	Body        []byte
}

func (h businessContextHandler) get(ctx context.Context, caller tenancy.User, _ *struct{}) (*body[businessContextResponse], error) {
	return businessContextOutput(h.contexts.Get(ctx, caller))
}

func (h businessContextHandler) save(ctx context.Context, caller tenancy.User, in *body[saveBusinessContextRequest]) (*body[businessContextResponse], error) {
	return businessContextOutput(h.contexts.Save(ctx, caller, in.Body.Version, in.Body.Context.fields()))
}

func (h businessContextHandler) brief(ctx context.Context, caller tenancy.User, _ *struct{}) (*briefOutput, error) {
	text, version, err := h.contexts.Brief(ctx, caller)
	if err != nil {
		return nil, err
	}
	return &briefOutput{ContentType: "text/markdown; charset=utf-8", ETag: strconv.Quote(strconv.Itoa(version)), Body: []byte(text)}, nil
}

func (h businessContextHandler) draft(ctx context.Context, caller tenancy.User, in *body[draftBusinessContextRequest]) (*body[draftResponse], error) {
	c, err := h.agents.DraftBusinessContext(ctx, caller, in.Body.documents())
	if err != nil {
		return nil, err
	}
	return &body[draftResponse]{Body: draftResponse{Context: newBusinessContextFields(c.Fields()), Gaps: c.Gaps()}}, nil
}

func (r draftBusinessContextRequest) documents() []agents.Document {
	docs := make([]agents.Document, 0, len(r.Files)+1)
	if r.Text != "" {
		docs = append(docs, agents.Document{Name: "pasted text", MediaType: "text/plain", Data: []byte(r.Text)})
	}
	for _, f := range r.Files {
		docs = append(docs, agents.Document{Name: f.Name, MediaType: f.MediaType, Data: f.Data})
	}
	return docs
}

func businessContextOutput(stored businesscontext.Stored, err error) (*body[businessContextResponse], error) {
	if err != nil {
		return nil, err
	}
	resp := businessContextResponse{
		Version:   stored.Version,
		Context:   newBusinessContextFields(stored.Context.Fields()),
		KeyFields: business.KeyFields(),
		Gaps:      stored.Context.Gaps(),
	}
	if stored.Version > 0 {
		resp.SavedAt, resp.SavedBy = &stored.Saved, &stored.SavedBy
	}
	return &body[businessContextResponse]{Body: resp}, nil
}
