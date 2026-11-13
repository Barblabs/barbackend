package httpapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"barbackend/internal/agents"
	"barbackend/internal/areas"
	"barbackend/internal/assessment"
	"barbackend/internal/assets"
	"barbackend/internal/businesscontext"
	"barbackend/internal/claude/claudetest"
	"barbackend/internal/cmdb"
	"barbackend/internal/cmdb/provider/providertest"
	"barbackend/internal/cognito/cognitotest"
	"barbackend/internal/encryption"
	"barbackend/internal/finding"
	"barbackend/internal/findings"
	"barbackend/internal/httpapi"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/scoring"
	"barbackend/internal/slack"
	"barbackend/internal/slack/slacktest"
	"barbackend/internal/stixext"
	"barbackend/internal/tenancy"
	"barbackend/internal/users"
	"github.com/TcM1911/stix2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const allowedOrigin = "http://localhost:5173"

var operations = []struct{ method, path string }{
	{http.MethodGet, "/cmdb/source"},
	{http.MethodPost, "/cmdb/source"},
	{http.MethodPut, "/cmdb/source"},
	{http.MethodDelete, "/cmdb/source"},
	{http.MethodPost, "/cmdb/source/test"},
	{http.MethodPost, "/cmdb/source/sync"},
	{http.MethodGet, "/assets"},
	{http.MethodGet, "/areas"},
	{http.MethodGet, "/prioritizations"},
	{http.MethodGet, "/business-context"},
	{http.MethodGet, "/business-context/brief"},
	{http.MethodGet, "/slack/installation"},
	{http.MethodGet, "/slack/channels"},
}

// platformOperations are those only a Platform Admin may call.
var platformOperations = []struct{ method, path string }{
	{http.MethodPost, "/customers"},
	{http.MethodGet, "/customers"},
	{http.MethodPatch, "/customers/" + uuid.Nil.String()},
	{http.MethodPost, "/customers/" + uuid.Nil.String() + "/deactivate"},
	{http.MethodPost, "/customers/" + uuid.Nil.String() + "/reactivate"},
}

// customerAdminOperations are those only a Customer Admin may call.
var customerAdminOperations = []struct{ method, path string }{
	{http.MethodGet, "/users"},
	{http.MethodPost, "/users"},
	{http.MethodPatch, "/users/" + uuid.Nil.String()},
	{http.MethodPost, "/users/" + uuid.Nil.String() + "/disable"},
	{http.MethodPut, "/areas/0/owner"},
	{http.MethodPut, "/assets/0/exposure"},
	{http.MethodDelete, "/assets/0/exposure"},
	{http.MethodPost, "/slack/install/start"},
	{http.MethodPut, "/slack/installation"},
	{http.MethodPost, "/slack/installation/test"},
	{http.MethodDelete, "/slack/installation"},
}

// businessContextEdits are those only a Customer Admin may call on the
// Business Context.
var businessContextEdits = []struct{ method, path string }{
	{http.MethodPut, "/business-context"},
	{http.MethodPost, "/business-context/draft"},
}

// everyRoleOperations are those every User may call, a Platform Admin included.
var everyRoleOperations = []struct{ method, path string }{
	{http.MethodGet, "/me"},
}

type env struct {
	db       *postgres.DB
	conn     *pgx.Conn
	pool     *cognitotest.Pool
	customer tenancy.CustomerID
	// token signs in a Viewer of customer.
	token    string
	provider *providertest.Provider
	admin    *fakeAdmin
	cmdb     *cmdb.Service
	key      encryption.Key
	slack    *slack.Service
	slackAPI *slacktest.Server
	llm      *claudetest.Server
	agents   *agents.Service
	router   http.Handler
}

func newEnv(t *testing.T) env {
	t.Helper()
	url := pgtest.URL(t)
	db, err := postgres.Open(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	p := &providertest.Provider{}
	pool := cognitotest.New(t)
	key := newKey(t)
	svc := cmdb.New(db, p.Providers(), key, context.Background(), time.Minute)
	admin := &fakeAdmin{}
	slackAPI := slacktest.New(t)
	slackService := slack.New(db, slackAPI.Client, key)
	llm := claudetest.New(t)
	agentService := agents.NewService(db, agents.NewCrew(llm.Client(), agents.DefaultModels()))
	router := httpapi.New(httpapi.Config{
		Agents: agentService, Areas: areas.New(db), Assets: assets.New(db, findings.New(db, scoring.Model1, time.Hour)), BusinessContext: businesscontext.New(db), CMDB: svc,
		Slack: slackService, Users: users.New(db, pool.Verifier(t), admin), AllowedOrigins: []string{allowedOrigin},
	})
	e := env{db: db, conn: pgtest.Conn(t, url), pool: pool, provider: p, admin: admin, cmdb: svc, key: key, slack: slackService, slackAPI: slackAPI, llm: llm, agents: agentService, router: router}
	e.customer = e.newCustomer(t)
	e.token = e.signIn(t, e.newUser(t, tenancy.Viewer, e.customer))
	return e
}

func (e env) newCustomer(t *testing.T) tenancy.CustomerID {
	t.Helper()
	id := uuid.New()
	if _, err := e.conn.Exec(context.Background(), "INSERT INTO customers (id, name) VALUES ($1, $2)", id, id.String()); err != nil {
		t.Fatal(err)
	}
	return tenancy.CustomerID(id)
}

// newUser stores a User and returns their Cognito sub.
func (e env) newUser(t *testing.T, role tenancy.Role, customer tenancy.CustomerID) string {
	t.Helper()
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), uuid.NewString()+"@example.com", role, customer)
	if err != nil {
		t.Fatal(err)
	}
	sub := uuid.NewString()
	if err := e.db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.CreateUser(context.Background(), u, sub)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return sub
}

// fakeAdmin is a user pool that invites every email under a new sub, or
// fails with err while it is set.
type fakeAdmin struct {
	mu      sync.Mutex
	err     error
	created []string
}

func (a *fakeAdmin) failWith(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.err = err
}

func (a *fakeAdmin) CreateUser(context.Context, string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return "", a.err
	}
	sub := uuid.NewString()
	a.created = append(a.created, sub)
	return sub, nil
}

func (a *fakeAdmin) invited() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.created)
}

func (e env) signIn(t *testing.T, sub string) string {
	t.Helper()
	return e.pool.AccessToken(t, sub)
}

func newKey(t *testing.T) encryption.Key {
	t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	key, err := encryption.ParseKey(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// connect connects a CMDB Source for customer, running its first Sync.
func (e env) connect(t *testing.T, customer tenancy.CustomerID) inventory.CMDBSourceID {
	t.Helper()
	if _, err := e.cmdb.Connect(context.Background(), viewerOf(customer), providertest.Name, providertest.Login); err != nil {
		t.Fatal(err)
	}
	var stored postgres.StoredCMDBSource
	if err := e.db.InTx(context.Background(), func(tx *postgres.Tx) (err error) {
		stored, err = tx.ConnectedCMDBSource(context.Background(), customer)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return stored.Source.ID()
}

// do sends req as the env's Viewer unless it carries its own Authorization.
func (e env) do(req *http.Request) *httptest.ResponseRecorder {
	if req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+e.token)
	}
	return e.send(req)
}

func (e env) send(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

type cmdbSource struct {
	Provider        string     `json:"provider"`
	URL             string     `json:"url"`
	User            string     `json:"user"`
	LastSync        *time.Time `json:"last_sync"`
	LastSyncFailure *struct {
		At    time.Time `json:"at"`
		Error string    `json:"error"`
	} `json:"last_sync_failure"`
}

func (e env) getCMDBSource(t *testing.T) (cmdbSource, string) {
	t.Helper()
	rec := e.do(httptest.NewRequest(http.MethodGet, "/cmdb/source", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s, want 200", rec.Code, rec.Body)
	}
	var got cmdbSource
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got, rec.Body.String()
}

func validLogin() map[string]string {
	return map[string]string{"provider": string(providertest.Name), "url": "http://cmdb", "user": "admin", "password": providertest.Secret}
}

func (e env) postLogin(path string, login map[string]string) *httptest.ResponseRecorder {
	return e.sendLogin(http.MethodPost, path, login)
}

func (e env) sendLogin(method, path string, login map[string]string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(login)
	return e.do(httptest.NewRequest(method, path, strings.NewReader(string(body))))
}

type syncResult struct {
	LastSync    *time.Time `json:"last_sync"`
	Created     int        `json:"created"`
	Updated     int        `json:"updated"`
	Deactivated int        `json:"deactivated"`
	Reactivated int        `json:"reactivated"`
	Skipped     int        `json:"skipped"`
}

type codedError struct {
	Code  string `json:"code"`
	Error string `json:"error"`
}

func (e env) sync(ctx context.Context) *httptest.ResponseRecorder {
	return e.do(httptest.NewRequestWithContext(ctx, http.MethodPost, "/cmdb/source/sync", nil))
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder, want int) T {
	t.Helper()
	var got T
	if rec.Code != want {
		t.Fatalf("status = %d %s, want %d", rec.Code, rec.Body, want)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func record(t *testing.T, id, name string) inventory.Record {
	t.Helper()
	imported, err := inventory.NewImportedAsset(inventory.ImportedAssetParams{Name: name, Kind: inventory.VirtualMachine})
	if err != nil {
		t.Fatal(err)
	}
	return inventory.Record{RecordID: id, Imported: imported}
}

func areaRecord(t *testing.T, id, name string) inventory.AreaRecord {
	t.Helper()
	imported, err := inventory.NewImportedArea(inventory.ImportedAreaParams{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	return inventory.AreaRecord{RecordID: id, Imported: imported}
}

// areaID is the id of the env Customer's Area with recordID.
func (e env) areaID(t *testing.T, recordID string) int64 {
	t.Helper()
	var id int64
	err := e.conn.QueryRow(context.Background(), `
		SELECT a.id FROM customer_areas a JOIN cmdb_sources s ON s.id = a.cmdb_source_id
		WHERE s.customer_id = $1 AND a.record_id = $2`, [16]byte(e.customer), recordID).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (e env) holdSyncLock(t *testing.T, src inventory.CMDBSourceID) (release func()) {
	t.Helper()
	locked, unlock, done := make(chan struct{}), make(chan struct{}), make(chan error)
	go func() {
		_, err := e.db.CommitSync(context.Background(), src, time.Now(), func(existing inventory.Stored) (inventory.Reconciliation, error) {
			close(locked)
			<-unlock
			return inventory.Reconcile(src, existing, inventory.Snapshot{})
		})
		done <- err
	}()
	<-locked
	return func() {
		close(unlock)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func viewerOf(customer tenancy.CustomerID) tenancy.User {
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "viewer@example.com", tenancy.Viewer, customer)
	if err != nil {
		panic(err)
	}
	return u
}

// prioritize stores two Findings on the Customer's pg-prod-01 and their
// Prioritization, in which the Prioritizer puts the one of CVE-2025-1094 first
// though the other has the higher Score.
func (e env) prioritize(t *testing.T) agents.Prioritization {
	t.Helper()
	ctx := context.Background()
	postgreSQL := inventory.SoftwareComponent{Role: inventory.Application, Name: "PostgreSQL", Version: "15.6", Product: inventory.Product{Vendor: "postgresql", Name: "postgresql"}}
	source, err := inventory.NewCMDBSource(inventory.CMDBSourceID(uuid.New()), e.customer, "fake")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.db.InTx(ctx, func(tx *postgres.Tx) error { return tx.CreateCMDBSource(ctx, source, []byte(`{}`), []byte{}) }); err != nil {
		t.Fatal(err)
	}
	imported, err := inventory.NewImportedAsset(inventory.ImportedAssetParams{Name: "pg-prod-01", Kind: inventory.Server, Criticality: inventory.CriticalityHigh, Software: []inventory.SoftwareComponent{postgreSQL}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := inventory.Snapshot{Records: []inventory.Record{{RecordID: "1", Imported: imported}}}
	if _, err := e.db.CommitSync(ctx, source.ID(), time.Now(), func(existing inventory.Stored) (inventory.Reconciliation, error) {
		return inventory.Reconcile(source.ID(), existing, snapshot)
	}); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i, cve := range []string{"CVE-2025-1094", "CVE-2024-6387"} {
		options := []stix2.STIXOption{stix2.OptionDescription("PostgreSQL is affected.")}
		if i == 0 {
			options = append(options, stix2.OptionExtension(string(stixext.KEVDefinitionID), stixext.NewKEV(stixext.KEV{DateAdded: "2025-02-13", RequiredAction: "Apply updates."})))
		}
		v, err := stix2.NewVulnerability(cve, options...)
		if err != nil {
			t.Fatal(err)
		}
		object, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		key, err := finding.NewKey(inventory.SourceReference{Source: source.ID(), RecordID: "1"}, postgreSQL.Product, cve)
		if err != nil {
			t.Fatal(err)
		}
		err = e.db.InTx(ctx, func(tx *postgres.Tx) error {
			if err := tx.StoreVulnerability(ctx, postgres.StoredVulnerability{CVE: cve, Object: object, Modified: time.Now()}); err != nil {
				return err
			}
			id, _, err := tx.SaveMatch(ctx, finding.Match{Key: key, Component: postgreSQL})
			if err != nil {
				return err
			}
			ids = append(ids, id.String())
			value := []float64{0.3, 0.6}[i]
			_, err = tx.SaveScoreIfChanged(ctx, id, scoring.Score{Model: 1, Value: value, Factors: scoring.Factors{Alpha: 0.5, Beta: 0.5, Vulnerability: value, CriticalityMultiplier: 1, ExposureMultiplier: 1}})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	e.llm.Queue(claudetest.JSON(t, assessment.Placement{Groups: []assessment.PlacedGroup{
		{Title: "Primero", Findings: ids[:1], Reason: "Va en pg-prod-01.", Evidence: []assessment.FindingEvidence{{Finding: ids[0], Path: "/asset/name", Value: "pg-prod-01"}}},
		{Title: "Después", Findings: ids[1:], Reason: "Sin KEV.", Evidence: []assessment.FindingEvidence{{Finding: ids[1], Path: "/kev", Value: "null"}}},
	}}))
	if _, err := e.agents.Prioritize(ctx, e.customer); err != nil {
		t.Fatal(err)
	}
	p, err := e.agents.Latest(ctx, viewerOf(e.customer))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// firstAndSecond are the ids of the Findings of the first and second groups
// of p.
func firstAndSecond(p agents.Prioritization) (string, string) {
	return p.List.Groups[0].Findings()[0], p.List.Groups[1].Findings()[0]
}

func jsonRequest(t *testing.T, method, path string, body any) *http.Request {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	return req
}

type prioritizationBody struct {
	ID                     string  `json:"id"`
	PreviousID             *string `json:"previous_id"`
	BusinessContextVersion *int    `json:"business_context_version"`
	Model                  string  `json:"model"`
	Groups                 []struct {
		Position   int      `json:"position"`
		Title      string   `json:"title"`
		FindingIDs []string `json:"finding_ids"`
		Evidence   []struct {
			FindingID string `json:"finding_id"`
			Path      string `json:"path"`
		} `json:"evidence"`
	} `json:"groups"`
	Findings []findingBody `json:"findings"`
	Plans    []struct {
		FindingID string `json:"finding_id"`
		Output    struct {
			Steps []string `json:"steps"`
		} `json:"output"`
	} `json:"plans"`
	Feedback []struct {
		FindingID   string `json:"finding_id"`
		Verdict     string `json:"verdict"`
		Note        string `json:"note"`
		ViaAnalista bool   `json:"via_analista"`
	} `json:"feedback"`
}

type findingBody struct {
	FindingID string  `json:"finding_id"`
	CVEID     string  `json:"cve_id"`
	Score     float64 `json:"score"`
	ScoreRank int     `json:"score_rank"`
	Group     int     `json:"group"`
	PlacedAt  string  `json:"placed_at"`
	ClosedAt  *string `json:"closed_at"`
	Details   struct {
		Description string `json:"description"`
		Asset       struct {
			Name             string `json:"name"`
			Criticality      string `json:"criticality"`
			CriticalServices []any  `json:"critical_services"`
		} `json:"asset"`
		ScoreDetails struct {
			Value    float64  `json:"value"`
			DataGaps []string `json:"data_gaps"`
		} `json:"score_details"`
		KEV *struct {
			DateAdded string `json:"date_added"`
		} `json:"kev"`
		Labeling struct {
			Outcome string `json:"outcome"`
		} `json:"labeling"`
		Techniques []any `json:"techniques"`
		Advisories []any `json:"advisories"`
	} `json:"details"`
}

func lunaReply(t *testing.T) claudetest.Reply {
	t.Helper()
	return claudetest.JSON(t, assessment.ActionPlan{Summary: "Revisa.", Steps: []string{"Confirma si aplica."}, Verification: "Confirma con el fabricante."})
}

// assetNamed is the Customer's Asset with that record id, Active or not.
func (e env) assetNamed(t *testing.T, recordID string) asset {
	t.Helper()
	return e.assetOf(t, "Bearer "+e.token, recordID)
}

// assetOf is the Asset with that record id of the Customer authorization
// signs in to.
func (e env) assetOf(t *testing.T, authorization, recordID string) asset {
	t.Helper()
	page := decode[assetList](t, e.asUser(authorization, http.MethodGet, "/assets?"+url.Values{"active": {"all"}}.Encode(), nil), http.StatusOK)
	i := slices.IndexFunc(page.Assets, func(a asset) bool { return a.RecordID == recordID })
	if i < 0 {
		t.Fatalf("no asset %q in %+v", recordID, page.Assets)
	}
	return page.Assets[i]
}

func (e env) userEmail(t *testing.T, id string) string {
	t.Helper()
	var email string
	if err := e.conn.QueryRow(context.Background(), "SELECT email FROM users WHERE id = $1", id).Scan(&email); err != nil {
		t.Fatal(err)
	}
	return email
}
