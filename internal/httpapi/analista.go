package httpapi

import (
	"context"
	"net/http"

	"barbackend/internal/agents"
	"barbackend/internal/tenancy"
	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
)

type analistaHandler struct {
	agents *agents.Service
}

func (h analistaHandler) register(api huma.API) {
	register(api, huma.Operation{
		OperationID:   "start-analista-conversation",
		Method:        http.MethodPost,
		Path:          "/analista/conversations",
		Summary:       "Start a conversation with the Analista",
		DefaultStatus: http.StatusCreated,
		Errors:        []int{http.StatusBadRequest, http.StatusBadGateway},
	}, h.start)
	register(api, huma.Operation{
		OperationID: "continue-analista-conversation",
		Method:      http.MethodPost,
		Path:        "/analista/conversations/{id}/messages",
		Summary:     "Send a message in one of the User's conversations with the Analista",
		Errors:      []int{http.StatusBadRequest, http.StatusNotFound, http.StatusConflict, http.StatusBadGateway},
	}, h.send)
}

type analistaMessage struct {
	Message string `json:"message" minLength:"1" maxLength:"8000"`
}

type startConversationRequest struct {
	Body analistaMessage
}

type continueConversationRequest struct {
	ID   uuid.UUID `path:"id" format:"uuid"`
	Body analistaMessage
}

type analistaAnswer struct {
	ConversationID string `json:"conversation_id"`
	Reply          string `json:"reply"`
}

func (h analistaHandler) start(ctx context.Context, caller tenancy.User, in *startConversationRequest) (*body[analistaAnswer], error) {
	answer, err := h.agents.Ask(ctx, caller, in.Body.Message)
	if err != nil {
		return nil, err
	}
	return &body[analistaAnswer]{Body: newAnalistaAnswer(answer)}, nil
}

func (h analistaHandler) send(ctx context.Context, caller tenancy.User, in *continueConversationRequest) (*body[analistaAnswer], error) {
	answer, err := h.agents.Continue(ctx, caller, in.ID, in.Body.Message)
	if err != nil {
		return nil, err
	}
	return &body[analistaAnswer]{Body: newAnalistaAnswer(answer)}, nil
}

func newAnalistaAnswer(a agents.Answer) analistaAnswer {
	return analistaAnswer{ConversationID: a.Conversation.String(), Reply: a.Reply}
}
