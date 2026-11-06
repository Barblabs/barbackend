package httpapi_test

import (
	"net/http"
	"strings"
	"testing"

	"barbackend/internal/business"
	"barbackend/internal/claude/claudetest"
	"barbackend/internal/tenancy"
)

type businessContextBody struct {
	Version   int      `json:"version"`
	SavedAt   *string  `json:"saved_at"`
	SavedBy   *string  `json:"saved_by"`
	Context   fields   `json:"context"`
	KeyFields []string `json:"key_fields"`
	Gaps      []string `json:"gaps"`
}

type fields struct {
	Profile struct {
		Summary   string   `json:"summary"`
		Sectors   []string `json:"sectors"`
		Employees string   `json:"employees"`
	} `json:"profile"`
	Geography struct {
		Headquarters string   `json:"headquarters"`
		Countries    []string `json:"countries"`
	} `json:"geography"`
	Operations struct {
		CriticalServices []struct {
			Name   string   `json:"name"`
			Assets []string `json:"assets"`
		} `json:"critical_services"`
	} `json:"operations"`
	Footprint struct {
		Domains []string `json:"domains"`
	} `json:"footprint"`
}

// contextFields is a Business Context as the dashboard sends it: every field,
// most of them not stated.
func contextFields(summary string) map[string]any {
	return map[string]any{
		"profile": map[string]any{
			"summary": summary, "mission": "", "vision": "", "sectors": []string{"retail"},
			"organization_type": "", "employees": "50_249", "annual_revenue": "",
		},
		"geography": map[string]any{"headquarters": "mx", "countries": []string{"CO"}},
		"operations": map[string]any{
			"critical_services": []map[string]any{{"name": "Tienda en línea", "description": "", "impact": "high", "max_downtime": "4h_24h", "assets": []string{"web-01"}}},
			"data_categories":   []string{"payment_cards"}, "regulations": []string{}, "environments": []string{},
		},
		"footprint": map[string]any{"domains": []string{"https://www.Zapatos.mx/"}, "brands": []string{}, "technologies": []string{}, "third_parties": []string{}},
		"risk":      map[string]any{"appetite": "", "concerns": []string{}, "past_incidents": "", "constraints": "", "notes": ""},
	}
}

func saveRequest(version int, summary string) map[string]any {
	return map[string]any{"version": version, "context": contextFields(summary)}
}

func TestBusinessContextStartsWithNothingStated(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	got := decode[businessContextBody](t, e.asUser("Bearer "+e.token, http.MethodGet, "/business-context", nil), http.StatusOK)

	if got.Version != 0 || got.SavedAt != nil || got.SavedBy != nil {
		t.Errorf("got version %d saved at %v by %v, want version 0 never saved", got.Version, got.SavedAt, got.SavedBy)
	}
	if len(got.KeyFields) == 0 || strings.Join(got.Gaps, ",") != strings.Join(got.KeyFields, ",") {
		t.Errorf("gaps = %v, want every key field %v", got.Gaps, got.KeyFields)
	}
	if got.Context.Profile.Sectors == nil || got.Context.Operations.CriticalServices == nil {
		t.Errorf("context = %+v, want empty lists, not null", got.Context)
	}
}

func TestACustomerAdminSavesVersionsEveryUserReads(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_, admin := e.customerAdmin(t, e.customer)

	first := decode[businessContextBody](t, e.asUser(admin, http.MethodPut, "/business-context", saveRequest(0, "Zapatos.")), http.StatusOK)
	if first.Version != 1 || first.SavedBy == nil || !strings.HasSuffix(*first.SavedBy, "@example.com") || first.SavedAt == nil {
		t.Errorf("first save = version %d by %v at %v, want version 1 by the admin", first.Version, first.SavedBy, first.SavedAt)
	}
	c := first.Context
	if c.Footprint.Domains[0] != "zapatos.mx" || strings.Join(c.Geography.Countries, ",") != "MX,CO" || c.Operations.CriticalServices[0].Assets[0] != "web-01" {
		t.Errorf("context = %+v, want it normalized", c)
	}

	read := decode[businessContextBody](t, e.asUser("Bearer "+e.token, http.MethodGet, "/business-context", nil), http.StatusOK)
	if read.Version != 1 || read.Context.Profile.Summary != "Zapatos." || len(read.Gaps) == 0 || len(read.Gaps) == len(read.KeyFields) {
		t.Errorf("a Viewer reads version %d %q with gaps %v, want version 1 and some gaps", read.Version, read.Context.Profile.Summary, read.Gaps)
	}

	stale := e.asUser(admin, http.MethodPut, "/business-context", saveRequest(0, "Bolsas."))
	if stale.Code != http.StatusConflict || !strings.Contains(stale.Body.String(), `"code":"business_context_stale"`) {
		t.Errorf("save on version 0 = %d %s, want 409 business_context_stale", stale.Code, stale.Body)
	}
	if second := decode[businessContextBody](t, e.asUser(admin, http.MethodPut, "/business-context", saveRequest(1, "Bolsas.")), http.StatusOK); second.Version != 2 {
		t.Errorf("save on version 1 = version %d, want 2", second.Version)
	}
}

func TestOnlyACustomerAdminEditsTheBusinessContext(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, role := range []tenancy.Role{tenancy.Viewer, tenancy.PlatformAdmin} {
		customer := e.customer
		if role == tenancy.PlatformAdmin {
			customer = tenancy.CustomerID{}
		}
		token := "Bearer " + e.signIn(t, e.newUser(t, role, customer))
		for _, op := range []struct {
			method, path string
			body         any
		}{
			{http.MethodPut, "/business-context", saveRequest(0, "Zapatos.")},
			{http.MethodPost, "/business-context/draft", map[string]string{"text": "Vendemos zapatos."}},
		} {
			rec := e.asUser(token, op.method, op.path, op.body)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"forbidden"`) {
				t.Errorf("%s: %s %s = %d %s, want 403 forbidden", role, op.method, op.path, rec.Code, rec.Body)
			}
		}
	}
	if got := decode[businessContextBody](t, e.asUser("Bearer "+e.token, http.MethodGet, "/business-context", nil), http.StatusOK); got.Version != 0 {
		t.Errorf("version = %d, want nothing saved", got.Version)
	}
	if n := len(e.llm.Requests()); n != 0 {
		t.Errorf("model requests = %d, want none", n)
	}
}

func TestSaveRejectsWhatIsNoBusinessContext(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_, admin := e.customerAdmin(t, e.customer)
	unknownSector := saveRequest(0, "Zapatos.")
	unknownSector["context"].(map[string]any)["profile"].(map[string]any)["sectors"] = []string{"zapatería"}
	tests := []struct {
		name string
		body any
		want string
	}{
		{"a code outside its vocabulary", unknownSector, "sectors"},
		{"too long a summary", saveRequest(0, strings.Repeat("a", business.MaxSummary+1)), "profile.summary"},
		{"no context", map[string]any{"version": 0}, "context"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := e.asUser(admin, http.MethodPut, "/business-context", tt.body)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"code":"invalid_request"`) || !strings.Contains(rec.Body.String(), tt.want) {
				t.Errorf("save = %d %s, want 400 invalid_request about %s", rec.Code, rec.Body, tt.want)
			}
		})
	}
}

func TestBriefIsTheBusinessContextAsMarkdown(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_, admin := e.customerAdmin(t, e.customer)
	decode[businessContextBody](t, e.asUser(admin, http.MethodPut, "/business-context", saveRequest(0, "Zapatos.")), http.StatusOK)

	rec := e.asUser("Bearer "+e.token, http.MethodGet, "/business-context/brief", nil)

	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/markdown") || rec.Header().Get("ETag") != `"1"` {
		t.Fatalf("brief = %d %v, want 200 Markdown with ETag \"1\"", rec.Code, rec.Header())
	}
	for _, want := range []string{"# Business context of " + e.customer.String(), "- Summary: Zapatos.", "- Sectors: Retail", "- Notes: not stated"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("brief lacks %q:\n%s", want, rec.Body)
		}
	}
}

func TestDraftProposesABusinessContextWithoutSavingIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_, admin := e.customerAdmin(t, e.customer)
	tests := []struct {
		name string
		body any
	}{
		{"from pasted text", map[string]string{"text": "Zapatos SA vende zapatos en zapatos.mx."}},
		{"from text and files together", map[string]any{"text": "Zapatos SA.", "files": []map[string]any{
			{"name": "perfil.pdf", "media_type": "application/pdf", "data": []byte("%PDF-1.7")},
			{"name": "notas.md", "media_type": "text/markdown", "data": []byte("Vendemos en zapatos.mx.")},
		}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.llm.Queue(claudetest.JSON(t, business.Fields{
				Profile:   business.Profile{Summary: "Vende zapatos.", Sectors: []business.Sector{"retail"}},
				Footprint: business.Footprint{Domains: []string{"Zapatos.mx"}},
			}))

			got := decode[struct {
				Context fields   `json:"context"`
				Gaps    []string `json:"gaps"`
			}](t, e.asUser(admin, http.MethodPost, "/business-context/draft", tt.body), http.StatusOK)

			if got.Context.Profile.Summary != "Vende zapatos." || got.Context.Footprint.Domains[0] != "zapatos.mx" || len(got.Gaps) == 0 {
				t.Errorf("draft = %+v with gaps %v", got.Context, got.Gaps)
			}
		})
	}
	if got := decode[businessContextBody](t, e.asUser(admin, http.MethodGet, "/business-context", nil), http.StatusOK); got.Version != 0 {
		t.Errorf("version = %d, want the drafts unsaved", got.Version)
	}
}

func TestDraftRefusesWhatItCannotRead(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_, admin := e.customerAdmin(t, e.customer)
	image := map[string]any{"name": "logo.png", "media_type": "image/png", "data": []byte{1}}
	for name, body := range map[string]any{
		"nothing":           map[string]any{},
		"an image":          map[string]any{"files": []any{image}},
		"text and an image": map[string]any{"text": "Zapatos.", "files": []any{image}},
	} {
		rec := e.asUser(admin, http.MethodPost, "/business-context/draft", body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"code":"invalid_document"`) {
			t.Errorf("%s: draft = %d %s, want 400 invalid_document", name, rec.Code, rec.Body)
		}
	}
	if n := len(e.llm.Requests()); n != 0 {
		t.Errorf("model requests = %d, want none", n)
	}
}

func TestDraftReportsADrafterWithoutAnAnswer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_, admin := e.customerAdmin(t, e.customer)
	e.llm.Queue(claudetest.Refusal())

	rec := e.asUser(admin, http.MethodPost, "/business-context/draft", map[string]string{"text": "Zapatos."})

	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), `"code":"agent_refused"`) {
		t.Errorf("draft = %d %s, want 502 agent_refused", rec.Code, rec.Body)
	}
}
