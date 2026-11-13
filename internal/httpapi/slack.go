package httpapi

import (
	"context"
	"html"
	"net/http"

	"barbackend/internal/slack"
	"barbackend/internal/tenancy"
	"github.com/danielgtaylor/huma/v2"
	"github.com/gin-gonic/gin"
)

type slackHandler struct {
	slack *slack.Service
}

func (h slackHandler) register(api huma.API) {
	register(api, huma.Operation{
		OperationID: "get-slack-installation",
		Method:      http.MethodGet,
		Path:        "/slack/installation",
		Summary:     "Get the Customer's Slack installation",
		Description: "Returns the workspace, the Security Team channel and the state, or null when Slack is not connected or was disconnected. Every role of the Customer can read it.",
		Responses:   nullableBody[slackInstallationResponse](api),
		Errors:      []int{http.StatusInternalServerError},
	}, h.get)
	register(api, huma.Operation{
		OperationID: "start-slack-install",
		Method:      http.MethodPost,
		Path:        "/slack/install/start",
		Summary:     "Start installing the Slack app",
		Description: "Returns the Slack authorize URL for the portal's popup. The state is sealed and names the Customer, so the callback needs no token.",
		Errors:      []int{http.StatusInternalServerError},
	}, h.start)
	register(api, huma.Operation{
		OperationID: "list-slack-channels",
		Method:      http.MethodGet,
		Path:        "/slack/channels",
		Summary:     "List the workspace's channels",
		Description: "Lists the workspace's public channels and the private ones the app has been added to through conversations.list, following Slack's cursor pagination, so the admin picks the Security Team channel from a list.",
		Errors:      []int{http.StatusNotFound, http.StatusConflict, http.StatusBadGateway},
	}, h.channels)
	register(api, huma.Operation{
		OperationID: "set-slack-channel",
		Method:      http.MethodPut,
		Path:        "/slack/installation",
		Summary:     "Set the Security Team channel",
		Description: "Stores the id and name of the channel chosen from GET /slack/channels.",
		Errors:      []int{http.StatusBadRequest, http.StatusNotFound, http.StatusConflict},
	}, h.setChannel)
	register(api, huma.Operation{
		OperationID: "test-slack-installation",
		Method:      http.MethodPost,
		Path:        "/slack/installation/test",
		Summary:     "Post a test message to the Security Team channel",
		Description: "Posts synchronously and returns Slack's answer, so the admin sees whether the connection works right now. A Slack refusal is a 200 with ok false and Slack's error code.",
		Errors:      []int{http.StatusNotFound, http.StatusConflict, http.StatusBadGateway},
	}, h.test)
	register(api, huma.Operation{
		OperationID: "disconnect-slack",
		Method:      http.MethodDelete,
		Path:        "/slack/installation",
		Summary:     "Disconnect the Customer's Slack workspace",
		Description: "Drops the bot token and removes the installation from the Customer's view. A later install returns it to active.",
	}, h.disconnect)
}

type slackInstallationResponse struct {
	TeamID      string `json:"team_id"`
	TeamName    string `json:"team_name"`
	ChannelID   string `json:"channel_id"`
	ChannelName string `json:"channel_name"`
	State       string `json:"state" enum:"active,needs re-authorisation,removed"`
}

type slackStartResponse struct {
	AuthorizeURL string `json:"authorize_url"`
}

type slackChannelResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	IsPrivate bool   `json:"is_private"`
}

type slackChannelsResponse struct {
	Channels []slackChannelResponse `json:"channels"`
}

type slackChannelRequest struct {
	_           struct{} `additionalProperties:"true"`
	ChannelID   string   `json:"channel_id" required:"false" doc:"The channel's id from GET /slack/channels"`
	ChannelName string   `json:"channel_name" required:"false" doc:"The channel's name, shown by the portal"`
}

type slackTestResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (h slackHandler) get(ctx context.Context, caller tenancy.User, _ *struct{}) (*body[*slackInstallationResponse], error) {
	installation, err := h.slack.Status(ctx, caller)
	if err != nil {
		return nil, err
	}
	return &body[*slackInstallationResponse]{Body: slackInstallationOutput(installation)}, nil
}

func (h slackHandler) start(ctx context.Context, caller tenancy.User, _ *struct{}) (*body[slackStartResponse], error) {
	url, err := h.slack.StartInstall(ctx, caller)
	if err != nil {
		return nil, err
	}
	return &body[slackStartResponse]{Body: slackStartResponse{AuthorizeURL: url}}, nil
}

func (h slackHandler) channels(ctx context.Context, caller tenancy.User, _ *struct{}) (*body[slackChannelsResponse], error) {
	channels, err := h.slack.Channels(ctx, caller)
	if err != nil {
		return nil, err
	}
	resp := slackChannelsResponse{Channels: make([]slackChannelResponse, len(channels))}
	for i, c := range channels {
		resp.Channels[i] = slackChannelResponse{ID: c.ID, Name: c.Name, IsPrivate: c.Private}
	}
	return &body[slackChannelsResponse]{Body: resp}, nil
}

func (h slackHandler) setChannel(ctx context.Context, caller tenancy.User, in *body[slackChannelRequest]) (*body[*slackInstallationResponse], error) {
	installation, err := h.slack.SetChannel(ctx, caller, in.Body.ChannelID, in.Body.ChannelName)
	if err != nil {
		return nil, err
	}
	return &body[*slackInstallationResponse]{Body: slackInstallationOutput(installation)}, nil
}

func (h slackHandler) test(ctx context.Context, caller tenancy.User, _ *struct{}) (*body[slackTestResponse], error) {
	result, err := h.slack.SendTest(ctx, caller)
	if err != nil {
		return nil, err
	}
	return &body[slackTestResponse]{Body: slackTestResponse{OK: result.OK, Error: result.Error}}, nil
}

func (h slackHandler) disconnect(ctx context.Context, caller tenancy.User, _ *struct{}) (*struct{}, error) {
	return &struct{}{}, h.slack.Disconnect(ctx, caller)
}

// callback is Slack redirecting the popup. It is a plain Gin route, not a
// Huma operation, because Slack carries no bearer token: the sealed state is
// what says which Customer is installing.
func (h slackHandler) callback(c *gin.Context) {
	if refused := c.Query("error"); refused != "" {
		h.callbackPage(c, http.StatusBadRequest, "Slack did not authorise the app: "+refused)
		return
	}
	err := h.slack.HandleCallback(c.Request.Context(), c.Query("code"), c.Query("state"))
	if err != nil {
		e := apiError(err)
		if e.cause != nil {
			_ = c.Error(e.cause)
		}
		h.callbackPage(c, e.status, e.Message)
		return
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, `<!doctype html><html><head><meta charset="utf-8"><title>Slack connected</title></head><body><p>Slack is connected. You can close this window.</p><script>window.close()</script></body></html>`)
}

func (h slackHandler) callbackPage(c *gin.Context, status int, message string) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(status, `<!doctype html><html><head><meta charset="utf-8"><title>Slack not connected</title></head><body><p>`+
		html.EscapeString(message)+`</p><button onclick="window.close()">Close</button></body></html>`)
}

func slackInstallationOutput(installation *slack.Installation) *slackInstallationResponse {
	if installation == nil {
		return nil
	}
	return &slackInstallationResponse{
		TeamID:      installation.TeamID,
		TeamName:    installation.TeamName,
		ChannelID:   installation.ChannelID,
		ChannelName: installation.ChannelName,
		State:       string(installation.State),
	}
}
