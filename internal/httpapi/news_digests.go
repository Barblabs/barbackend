package httpapi

import (
	"context"
	"net/http"
	"slices"
	"time"

	"barbackend/internal/agents"
	"barbackend/internal/news"
	"barbackend/internal/tenancy"
	"github.com/danielgtaylor/huma/v2"
)

type newsDigestHandler struct {
	agents *agents.Service
}

func (h newsDigestHandler) register(api huma.API) {
	register(api, huma.Operation{
		OperationID: "list-news-digests",
		Method:      http.MethodGet,
		Path:        "/news-digests",
		Summary:     "List the Customer's News Digests, newest first",
		Description: "The Editor writes one a day when news about attacks and Vulnerabilities is relevant to the Customer (ADR 0025).",
		Errors:      []int{http.StatusBadRequest},
	}, h.list)
	register(api, huma.Operation{
		OperationID: "get-news-digest",
		Method:      http.MethodGet,
		Path:        "/news-digests/{id}",
		Summary:     "Read a News Digest: its News Items by Relevance, closest first, with why each may matter",
		Errors:      []int{http.StatusNotFound},
	}, h.get)
}

type newsDigestListQuery struct {
	Limit prioritizationPageSize `query:"limit" doc:"Page size"`
}

type newsCountsResponse struct {
	Named     int `json:"named" doc:"News Items whose victim is the Customer itself"`
	Finding   int `json:"finding" doc:"News Items that name the Vulnerability of an open Finding"`
	Footprint int `json:"footprint" doc:"News Items that name a Product its Assets run, or a technology or third party its Business Context states"`
	Peer      int `json:"peer" doc:"Attacks on organizations of its sector: context, not exposure"`
}

type newsDigestSummaryResponse struct {
	ID        string             `json:"id"`
	CreatedAt time.Time          `json:"created_at"`
	Since     time.Time          `json:"since" doc:"It holds the News Items that became ready after since and up to until"`
	Until     time.Time          `json:"until"`
	Counts    newsCountsResponse `json:"counts"`
}

type newsDigestListResponse struct {
	NewsDigests []newsDigestSummaryResponse `json:"news_digests"`
}

type newsDigestResponse struct {
	newsDigestSummaryResponse
	BusinessContextVersion *int                `json:"business_context_version" doc:"The version of the Business Context the Editor read, null when the Customer had stated none"`
	NoSectors              bool                `json:"no_sectors" doc:"The Business Context states no sector, so no attack on a Peer can reach the Customer"`
	Editor                 editorRunResponse   `json:"editor"`
	Groups                 []newsGroupResponse `json:"groups" doc:"One per Relevance that has News Items, closest first"`
}

type editorRunResponse struct {
	Status   string `json:"status" enum:"verified,rejected,refused,failed" doc:"Only a verified Editor gives each News Item its why; otherwise the digest keeps the rules' order"`
	Model    string `json:"model"`
	PromptID string `json:"prompt_id"`
}

type newsGroupResponse struct {
	Relevance string             `json:"relevance" enum:"named,finding,footprint,peer"`
	Items     []newsItemResponse `json:"items" doc:"In the order to read them"`
}

type newsItemResponse struct {
	NewsItemID      string                    `json:"news_item_id"`
	Feed            string                    `json:"feed"`
	Kind            string                    `json:"kind" enum:"article,leak_post" doc:"A leak_post is the attacker's own claim"`
	Title           string                    `json:"title"`
	Link            string                    `json:"link"`
	Language        string                    `json:"language"`
	PublishedAt     time.Time                 `json:"published_at"`
	Summary         *string                   `json:"summary" doc:"What the Reader states happened, in Spanish; null when it did not read the item"`
	Excerpt         *string                   `json:"excerpt" doc:"The item's own text, for an item without a summary"`
	Labels          []string                  `json:"labels" doc:"Written by code; show them as they are, they must not be missed"`
	Reasons         []string                  `json:"reasons" doc:"Why the rules found it relevant, written by code, closest first"`
	Why             *string                   `json:"why" doc:"Why it may matter to the Customer, by the Editor; null when the Editor had no verified answer"`
	ContextEvidence []contextEvidenceResponse `json:"context_evidence" doc:"What the why relies on from the Business Context"`
	Attacks         []newsAttackResponse      `json:"attacks" doc:"The attacks it reports: the source's claim, never confirmed"`
	CVEIDs          []string                  `json:"cve_ids"`
}

type newsAttackResponse struct {
	Victim    string   `json:"victim" doc:"Blank when the item names no victim"`
	Domain    *string  `json:"domain"`
	Sectors   []string `json:"sectors" doc:"Codes of the Business Context's sector vocabulary"`
	Countries []string `json:"countries" doc:"ISO 3166-1 alpha-2"`
	Kind      *string  `json:"kind" doc:"A code of the Business Context's concerns vocabulary, null when the item does not say"`
	Attacker  *string  `json:"attacker"`
}

func (h newsDigestHandler) list(ctx context.Context, caller tenancy.User, in *newsDigestListQuery) (*body[newsDigestListResponse], error) {
	list, err := h.agents.NewsDigests(ctx, caller, int(in.Limit))
	if err != nil {
		return nil, err
	}
	resp := newsDigestListResponse{NewsDigests: make([]newsDigestSummaryResponse, len(list))}
	for i, d := range list {
		resp.NewsDigests[i] = newsDigestSummary(d)
	}
	return &body[newsDigestListResponse]{Body: resp}, nil
}

func (h newsDigestHandler) get(ctx context.Context, caller tenancy.User, in *idPath) (*body[newsDigestResponse], error) {
	d, err := h.agents.GetNewsDigest(ctx, caller, in.ID)
	if err != nil {
		return nil, err
	}
	resp := newsDigestResponse{
		newsDigestSummaryResponse: newsDigestSummary(d),
		NoSectors:                 d.NoSectors,
		Editor:                    editorRunResponse{Status: string(d.Editor.Status), Model: d.Editor.Model, PromptID: d.Editor.PromptID},
		Groups:                    []newsGroupResponse{},
	}
	if d.BusinessContext > 0 {
		resp.BusinessContextVersion = &d.BusinessContext
	}
	for _, relevance := range news.Relevances() {
		group := newsGroupResponse{Relevance: string(relevance)}
		for _, e := range d.Entries {
			if e.Relevance == relevance {
				group.Items = append(group.Items, newsItem(e))
			}
		}
		if len(group.Items) > 0 {
			resp.Groups = append(resp.Groups, group)
		}
	}
	return &body[newsDigestResponse]{Body: resp}, nil
}

func newsDigestSummary(d agents.NewsDigest) newsDigestSummaryResponse {
	return newsDigestSummaryResponse{
		ID: d.ID.String(), CreatedAt: d.Created, Since: d.Since, Until: d.Until,
		Counts: newsCountsResponse{Named: d.Counts.Named, Finding: d.Counts.Finding, Footprint: d.Counts.Footprint, Peer: d.Counts.Peer},
	}
}

func newsItem(e agents.DigestEntry) newsItemResponse {
	item := newsItemResponse{
		NewsItemID: e.NewsItem, Feed: e.Feed, Kind: e.Kind, Title: e.Title, Link: e.Link, Language: e.Language,
		PublishedAt: e.Published, Summary: optional(e.Summary), Excerpt: optional(e.Excerpt), Why: optional(e.Why),
		Labels: slices.Clip(append([]string{}, e.Labels...)), Reasons: make([]string, len(e.Reasons)),
		ContextEvidence: make([]contextEvidenceResponse, len(e.ContextEvidence)),
		Attacks:         make([]newsAttackResponse, len(e.Attacks)), CVEIDs: append([]string{}, e.CVEs...),
	}
	for i, r := range e.Reasons {
		item.Reasons[i] = r.Text
	}
	for i, ev := range e.ContextEvidence {
		item.ContextEvidence[i] = contextEvidenceResponse{Path: ev.Path, Value: ev.Value}
	}
	for i, a := range e.Attacks {
		sectors := make([]string, len(a.Sectors))
		for j, s := range a.Sectors {
			sectors[j] = string(s)
		}
		item.Attacks[i] = newsAttackResponse{
			Victim: a.Victim, Domain: optional(a.Domain), Sectors: sectors, Countries: append([]string{}, a.Countries...),
			Kind: optional(string(a.Kind)), Attacker: optional(a.Attacker),
		}
	}
	return item
}

// optional is s, or null when it is blank.
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
