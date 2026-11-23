package httpapi

import (
	"context"
	"net/http"
	"time"

	"barbackend/internal/agents"
	"barbackend/internal/tenancy"
	"github.com/danielgtaylor/huma/v2"
)

func (h prioritizationHandler) registerHistory(api huma.API) {
	register(api, huma.Operation{
		OperationID: "get-finding-history",
		Method:      http.MethodGet,
		Path:        "/findings/{id}/history",
		Summary:     "Tell how the Customer's order placed one Finding, and why each change",
		Description: "One entry per Prioritization where the Finding's place changed, newest first: placed, placed_again when a round placed it again, moved when other groups moved it, left when it closed. Each gives, before and now, the Finding's group, where that group sits in the Prioritizer's order Finding by Finding, its rank by Score alone and its Score, so the two orders compare, and the Prioritizer's justification as it wrote it. placed_again also says what changed in the Finding. It calls no Agent. Empty for a Finding no Prioritization held.",
		Errors:      []int{http.StatusBadRequest, http.StatusNotFound},
	}, h.history)
}

type historyResponse struct {
	Entries []historyEntryResponse `json:"entries"`
}

type historyEntryResponse struct {
	PrioritizationID string                    `json:"prioritization_id"`
	CreatedAt        time.Time                 `json:"created_at" doc:"When that Prioritization was made"`
	Kind             string                    `json:"kind" enum:"placed,placed_again,moved,left"`
	GroupBefore      *int                      `json:"group_before" doc:"Position of its Priority Group in the Prioritization before, from 1; null for placed"`
	GroupNow         *int                      `json:"group_now" doc:"Position of its Priority Group in this one, from 1; null for left"`
	RankBefore       *int                      `json:"rank_before" doc:"Where its Score alone put it before, 1 the highest; null for placed"`
	RankNow          *int                      `json:"rank_now" doc:"Where its Score alone puts it now; null for left"`
	OrderBefore      *orderResponse            `json:"order_before" doc:"Where its group sat in the Prioritizer's order before, counted Finding by Finding: a group's Findings are attended at the same time, so it is anywhere from to to; null for placed"`
	OrderNow         *orderResponse            `json:"order_now" doc:"Where its group sits in the Prioritizer's order now; null for left"`
	ScoreBefore      *float64                  `json:"score_before" doc:"Its Score as the Prioritizer read it before; null for placed"`
	ScoreNow         *float64                  `json:"score_now" doc:"Its Score as the Prioritizer read it now; null for left"`
	Title            string                    `json:"title" doc:"The title of its Priority Group; empty for left"`
	Reason           string                    `json:"reason" doc:"The Prioritizer's reason for the part of the group that holds it, as it wrote it when it last placed the Finding; render it as plain text"`
	Evidence         []historyEvidenceResponse `json:"evidence" doc:"What that reason cites of this Finding"`
	Changes          []string                  `json:"changes" doc:"For placed_again, what changed in the Finding since it was last placed: kev_listed, ransomware_use, labeled, band_changed, score_moved, feedback, business_context. Empty when none of the rules applies"`
	Band             *bandChangeResponse       `json:"band" doc:"For band_changed, its Score Bands before and now"`
	Feedback         []historyFeedbackResponse `json:"feedback" doc:"For placed_again, what Users said directly about where it should be since it was last placed"`
	GroupsAppeared   []string                  `json:"groups_appeared" doc:"For moved, the titles of the groups above it now that were not above it before"`
	GroupsGone       []string                  `json:"groups_gone" doc:"For moved, the titles of the groups above it before that are not now"`
	CloseReason      *string                   `json:"close_reason" doc:"For the newest entry when it is left and the Finding is still closed, why it closed"`
}

type historyEvidenceResponse struct {
	Path  string `json:"path" doc:"RFC 6901 pointer into what the Prioritizer read of the Finding"`
	Value string `json:"value"`
}

type bandChangeResponse struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type orderResponse struct {
	From int `json:"from" doc:"From 1"`
	To   int `json:"to"`
}

type historyFeedbackResponse struct {
	Verdict   string    `json:"verdict" enum:"should_be_earlier,should_be_later"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}

func (h prioritizationHandler) history(ctx context.Context, caller tenancy.User, in *findingPath) (*body[historyResponse], error) {
	entries, err := h.agents.FindingHistory(ctx, caller, in.ID.String())
	if err != nil {
		return nil, err
	}
	resp := historyResponse{Entries: make([]historyEntryResponse, len(entries))}
	for i, e := range entries {
		resp.Entries[i] = newHistoryEntry(e)
	}
	return &body[historyResponse]{Body: resp}, nil
}

func newHistoryEntry(e agents.HistoryEntry) historyEntryResponse {
	out := historyEntryResponse{
		PrioritizationID: e.Prioritization, CreatedAt: e.Created, Kind: string(e.Kind),
		GroupBefore: positive(e.GroupBefore), GroupNow: positive(e.GroupNow), RankBefore: positive(e.RankBefore), RankNow: positive(e.RankNow),
		Title: e.Title, Reason: e.Reason,
		Evidence:       make([]historyEvidenceResponse, len(e.Evidence)),
		Changes:        []string{},
		Feedback:       make([]historyFeedbackResponse, len(e.Feedback)),
		GroupsAppeared: append([]string{}, e.GroupsAppeared...),
		GroupsGone:     append([]string{}, e.GroupsGone...),
	}
	for i, ev := range e.Evidence {
		out.Evidence[i] = historyEvidenceResponse{Path: ev.Path, Value: ev.Value}
	}
	for i, f := range e.Feedback {
		out.Feedback[i] = historyFeedbackResponse{Verdict: f.Verdict, Note: f.Note, CreatedAt: f.At}
	}
	if e.GroupBefore != 0 {
		out.OrderBefore = &orderResponse{From: e.OrderBefore.From, To: e.OrderBefore.To}
		out.ScoreBefore = &e.ScoreBefore
	}
	if e.GroupNow != 0 {
		out.OrderNow = &orderResponse{From: e.OrderNow.From, To: e.OrderNow.To}
		out.ScoreNow = &e.ScoreNow
	}
	if e.CloseReason != "" {
		out.CloseReason = &e.CloseReason
	}
	if e.PlacedAgain() {
		out.Changes = e.ChangeCodes()
		if e.Change.BandFrom != "" {
			out.Band = &bandChangeResponse{From: e.Change.BandFrom, To: e.Change.BandTo}
		}
	}
	return out
}

// positive is n, or nil when it is 0, which a history entry has for no place.
func positive(n int) *int {
	if n == 0 {
		return nil
	}
	return &n
}
