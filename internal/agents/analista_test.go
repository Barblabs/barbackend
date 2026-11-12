package agents_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"barbackend/internal/agents"
	"barbackend/internal/claude/claudetest"
	"barbackend/internal/postgres"
	"github.com/google/uuid"
)

func TestAskAnswersFromTheCustomersData(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	if _, err := e.svc.RecordFeedback(context.Background(), e.user, p.ID, e.pg(), "remediated", "ya"); err != nil {
		t.Fatal(err)
	}
	e.llm.Queue(
		claudetest.ToolCall("1", "get_prioritization", map[string]any{"prioritization_id": nil}),
		claudetest.ToolCall("2", "get_finding", map[string]any{"prioritization_id": p.ID.String(), "finding_id": e.pg()}),
		claudetest.ToolCall("3", "list_assets", map[string]any{"criticality": "high"}),
		claudetest.ToolCall("4", "list_assets", map[string]any{"criticality": "low"}),
		claudetest.Text("Tienes un hallazgo."),
	)

	answer, err := e.svc.Ask(context.Background(), e.user, "¿qué tengo pendiente?")
	if err != nil {
		t.Fatal(err)
	}

	if answer.Reply != "Tienes un hallazgo." || answer.Conversation == uuid.Nil {
		t.Errorf("answer = %+v", answer)
	}
	requests := e.llm.Requests()[1:]
	first := requests[0]
	if first["model"] != "claude-opus-5-5" || first["fallbacks"] != "default" {
		t.Errorf("model = %v, fallbacks = %v", first["model"], first["fallbacks"])
	}
	contains(t, system(first), "You are the Analista")
	for i, want := range []string{p.ID.String(), `"verdict":"remediated"`, "pg-prod-01", `"total":0`} {
		result, isError := toolResult(t, requests[i+1])
		if isError {
			t.Errorf("tool %d failed: %s", i, result)
		}
		contains(t, result, want)
	}
}

func TestAnalistaRecordsWhatTheUserSays(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	e.llm.Queue(
		claudetest.ToolCall("1", "record_feedback", map[string]any{"prioritization_id": p.ID.String() + "\n", "finding_id": e.pg(), "verdict": "remediated", "note": "parchado ayer"}),
		claudetest.Text("Lo registré."),
	)

	if _, err := e.svc.Ask(context.Background(), e.user, "ya lo parchamos ayer"); err != nil {
		t.Fatal(err)
	}

	got, err := e.svc.Get(context.Background(), e.user, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Feedback) != 1 {
		t.Fatalf("feedback = %+v", got.Feedback)
	}
	f := got.Feedback[0]
	if f.Verdict.Code() != "remediated" || f.Note != "parchado ayer" || !f.ViaAnalista || f.Author != e.user.ID() {
		t.Errorf("feedback = %+v", f)
	}
}

func TestContinueStoresWhatTheUserSays(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	e.llm.Queue(claudetest.Text("hola"))
	first, err := e.svc.Ask(context.Background(), e.user, "hola")
	if err != nil {
		t.Fatal(err)
	}
	call := func(id string) claudetest.Reply {
		return claudetest.ToolCall(id, "record_feedback", map[string]any{"prioritization_id": p.ID.String(), "finding_id": e.pg(), "verdict": "applies", "note": "sigue ahí"})
	}
	e.llm.Queue(call("1"), call("2"), claudetest.Text("Lo registré."))

	if _, err := e.svc.Continue(context.Background(), e.user, first.Conversation, "sí aplica"); err != nil {
		t.Fatal(err)
	}

	got, err := e.svc.Get(context.Background(), e.user, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Feedback) != 1 || got.Feedback[0].Note != "sigue ahí" || !got.Feedback[0].ViaAnalista {
		t.Errorf("feedback = %+v, want the one the User gave, however often the model recorded it", got.Feedback)
	}
}

func TestAMessageOvertakenWhileAnsweredStoresNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	e.llm.Queue(claudetest.Text("hola"))
	first, err := e.svc.Ask(context.Background(), e.user, "hola")
	if err != nil {
		t.Fatal(err)
	}
	customer, err := e.user.ActsFor()
	if err != nil {
		t.Fatal(err)
	}
	owner := postgres.ConversationOwner{Customer: customer, User: e.user.ID()}
	e.llm.Queue(
		claudetest.ToolCall("1", "record_feedback", map[string]any{"prioritization_id": p.ID.String(), "finding_id": e.pg(), "verdict": "applies", "note": "x"}),
		claudetest.Text("Lo registré."),
	)
	release := e.llm.Hold()

	var wg sync.WaitGroup
	var overtaken error
	wg.Go(func() {
		_, overtaken = e.svc.Continue(context.Background(), e.user, first.Conversation, "sí aplica")
	})
	waitForRequests(t, e, 3)
	err = e.db.InTx(context.Background(), func(tx *postgres.Tx) error {
		return tx.AdvanceConversation(context.Background(), owner, first.Conversation, 1, json.RawMessage(`[]`))
	})
	if err != nil {
		t.Fatal(err)
	}
	release()
	wg.Wait()

	wantErr(t, overtaken, agents.ErrConversationBusy)
	got, err := e.svc.Get(context.Background(), e.user, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Feedback) != 0 {
		t.Errorf("feedback = %+v, want it rolled back", got.Feedback)
	}
}

func TestATurnWithoutTextIsNoAnswer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	record := claudetest.ToolCall("1", "record_feedback", map[string]any{"prioritization_id": p.ID.String(), "finding_id": e.pg(), "verdict": "applies", "note": "x"})
	e.llm.Queue(record, claudetest.Empty())

	_, err := e.svc.Ask(context.Background(), e.user, "sí aplica")

	wantErr(t, err, agents.ErrUnavailable)
	got, err := e.svc.Get(context.Background(), e.user, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Feedback) != 0 {
		t.Errorf("feedback = %+v, want none from a turn without an answer", got.Feedback)
	}
}

func TestATurnThatFailsStoresNoFeedback(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	record := func(id string) claudetest.Reply {
		return claudetest.ToolCall(id, "record_feedback", map[string]any{"prioritization_id": p.ID.String(), "finding_id": e.pg(), "verdict": "remediated", "note": "x"})
	}
	e.llm.Queue(record("1"), claudetest.Refusal())
	_, err := e.svc.Ask(context.Background(), e.user, "ya lo parchamos")
	wantErr(t, err, agents.ErrRefused)

	e.llm.Queue(claudetest.Text("hola"))
	answer, err := e.svc.Ask(context.Background(), e.user, "hola")
	if err != nil {
		t.Fatal(err)
	}
	e.llm.Queue(record("2"), claudetest.Fail(http.StatusUnauthorized))
	_, err = e.svc.Continue(context.Background(), e.user, answer.Conversation, "ya lo parchamos")
	wantErr(t, err, agents.ErrUnavailable)

	got, err := e.svc.Get(context.Background(), e.user, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Feedback) != 0 {
		t.Errorf("feedback = %+v, want none from a turn that failed", got.Feedback)
	}
}

func TestAnalistaToolsStayInTheCallersCustomer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	theirs := e.prioritize(t)
	stranger := e.newCustomer(t, "strangers-own-asset")
	id := theirs.ID.String()
	e.llm.Queue(
		claudetest.ToolCall("1", "get_finding", map[string]any{"prioritization_id": id, "finding_id": e.pg()}),
		claudetest.ToolCall("2", "record_feedback", map[string]any{"prioritization_id": id, "finding_id": e.pg(), "verdict": "does_not_apply", "note": "x"}),
		claudetest.ToolCall("3", "get_prioritization", map[string]any{"prioritization_id": id}),
		claudetest.ToolCall("4", "get_prioritization", map[string]any{"prioritization_id": nil}),
		claudetest.ToolCall("5", "list_assets", map[string]any{"criticality": nil}),
		claudetest.Text("No lo encuentro."),
	)

	if _, err := e.svc.Ask(context.Background(), stranger, "enséñame la priorización "+id); err != nil {
		t.Fatal(err)
	}

	requests := e.llm.Requests()[1:]
	for _, i := range []int{1, 2, 3, 4} {
		result, isError := toolResult(t, requests[i])
		if !isError || !strings.Contains(result, agents.ErrPrioritizationNotFound.Error()) {
			t.Errorf("tool %d = %s, want not found", i, result)
		}
	}
	result, _ := toolResult(t, requests[5])
	contains(t, result, "strangers-own-asset")
	if strings.Contains(result, "pg-prod-01") {
		t.Errorf("list_assets = %s, holds another Customer's Asset", result)
	}
	got, err := e.svc.Get(context.Background(), e.user, theirs.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Feedback) != 0 {
		t.Errorf("feedback = %+v, want none from another Customer", got.Feedback)
	}
}

func TestAnalistaToolsTellTheModelOnlyWhatItCanCorrect(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := e.prioritize(t)
	e.llm.Queue(
		claudetest.ToolCall("1", "get_finding", map[string]any{"prioritization_id": "not-a-uuid", "finding_id": e.pg()}),
		claudetest.ToolCall("2", "record_feedback", map[string]any{"prioritization_id": p.ID.String(), "finding_id": e.pg(), "verdict": "maybe", "note": "x"}),
		claudetest.ToolCall("3", "list_assets", map[string]any{"criticality": "huge"}),
		claudetest.Text("Fin."),
	)
	if _, err := e.svc.Ask(context.Background(), e.user, "hola"); err != nil {
		t.Fatal(err)
	}
	requests := e.llm.Requests()[1:]
	for i, want := range []string{"prioritization_id", "invalid verdict", "invalid criticality"} {
		result, isError := toolResult(t, requests[i+1])
		if !isError {
			t.Errorf("tool %d = %s, want an error", i, result)
		}
		contains(t, result, want)
	}

	broken := newEnv(t)
	broken.llm.Queue(claudetest.ToolCall("1", "get_prioritization", map[string]any{"prioritization_id": nil}), claudetest.Text("Fin."))
	broken.db.Close()
	if _, err := broken.svc.Ask(context.Background(), broken.user, "hola"); err == nil {
		t.Error("err = nil, want the conversation not stored without a database")
	}
	if result, isError := toolResult(t, broken.llm.Requests()[1]); !isError || result != "internal error" {
		t.Errorf("tool = %s, want a database failure hidden from the model", result)
	}
}

func TestContinueSendsTheConversationBackWithItsToolCalls(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.llm.Queue(claudetest.ToolCall("1", "list_assets", map[string]any{"criticality": nil}), claudetest.Text("primera"), claudetest.Text("segunda"))

	first, err := e.svc.Ask(context.Background(), e.user, "uno")
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.svc.Continue(context.Background(), e.user, first.Conversation, "dos")
	if err != nil {
		t.Fatal(err)
	}

	if second.Conversation != first.Conversation || second.Reply != "segunda" {
		t.Errorf("answer = %+v", second)
	}
	messages := e.llm.Requests()[2]["messages"].([]any)
	if len(messages) != 5 {
		t.Fatalf("messages = %d, want the whole conversation", len(messages))
	}
	content := messages[1].(map[string]any)["content"].([]any)
	thinking, call := content[0].(map[string]any), content[1].(map[string]any)
	if thinking["signature"] != "signature" || call["type"] != "tool_use" {
		t.Errorf("stored blocks = %v, want them as they came", content)
	}
}

func TestAConversationBelongsToItsUser(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.llm.Queue(claudetest.Text("hola"))
	answer, err := e.svc.Ask(context.Background(), e.user, "uno")
	if err != nil {
		t.Fatal(err)
	}
	customer, err := e.user.ActsFor()
	if err != nil {
		t.Fatal(err)
	}
	colleague := newUser(t, e.user.Role(), customer)
	stranger := e.newCustomer(t, "theirs")

	_, err = e.svc.Continue(context.Background(), colleague, answer.Conversation, "dos")
	wantErr(t, err, agents.ErrConversationNotFound)
	_, err = e.svc.Continue(context.Background(), stranger, answer.Conversation, "dos")
	wantErr(t, err, agents.ErrConversationNotFound)
	_, err = e.svc.Continue(context.Background(), e.user, uuid.New(), "dos")
	wantErr(t, err, agents.ErrConversationNotFound)
}

func TestContinueRefusesAMessageWhileAnotherIsBeingAnswered(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.llm.Queue(claudetest.Text("hola"))
	first, err := e.svc.Ask(context.Background(), e.user, "uno")
	if err != nil {
		t.Fatal(err)
	}
	e.llm.Queue(claudetest.Text("a"))
	release := e.llm.Hold()

	var wg sync.WaitGroup
	var answering error
	wg.Go(func() {
		_, answering = e.svc.Continue(context.Background(), e.user, first.Conversation, "dos")
	})
	waitForRequests(t, e, 2)

	_, err = e.svc.Continue(context.Background(), e.user, first.Conversation, "tres")
	wantErr(t, err, agents.ErrConversationBusy)
	if got := len(e.llm.Requests()); got != 2 {
		t.Errorf("requests = %d, want the refused message not to reach the model", got)
	}

	release()
	wg.Wait()
	if answering != nil {
		t.Errorf("the message being answered: err = %v", answering)
	}
	e.llm.Queue(claudetest.Text("b"))
	if _, err := e.svc.Continue(context.Background(), e.user, first.Conversation, "cuatro"); err != nil {
		t.Errorf("after the answer: err = %v", err)
	}
}

func TestACancelledRequestLeavesTheConversationUsable(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.llm.Queue(claudetest.Text("hola"))
	first, err := e.svc.Ask(context.Background(), e.user, "uno")
	if err != nil {
		t.Fatal(err)
	}
	e.llm.Queue(claudetest.Text("nadie lo lee"))
	release := e.llm.Hold()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	var cancelled error
	wg.Go(func() {
		_, cancelled = e.svc.Continue(ctx, e.user, first.Conversation, "dos")
	})
	waitForRequests(t, e, 2)
	cancel()
	wg.Wait()
	release()

	wantErr(t, cancelled, agents.ErrUnavailable)
	e.llm.Queue(claudetest.Text("tres"))
	if _, err := e.svc.Continue(context.Background(), e.user, first.Conversation, "otra vez"); err != nil {
		t.Errorf("after a cancelled request: err = %v", err)
	}
}

func TestContinueRejectsABlankMessageAndStaysUsable(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.llm.Queue(claudetest.Text("hola"))
	first, err := e.svc.Ask(context.Background(), e.user, "uno")
	if err != nil {
		t.Fatal(err)
	}

	_, err = e.svc.Continue(context.Background(), e.user, first.Conversation, "  ")
	wantErr(t, err, agents.ErrEmptyMessage)

	e.llm.Queue(claudetest.Text("dos"))
	if _, err := e.svc.Continue(context.Background(), e.user, first.Conversation, "dos"); err != nil {
		t.Errorf("after a blank message: err = %v", err)
	}
}

func TestAFailedTurnLeavesTheConversationUsable(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.llm.Queue(claudetest.Text("hola"))
	first, err := e.svc.Ask(context.Background(), e.user, "uno")
	if err != nil {
		t.Fatal(err)
	}
	e.llm.Queue(claudetest.Refusal())
	_, err = e.svc.Continue(context.Background(), e.user, first.Conversation, "dos")
	wantErr(t, err, agents.ErrRefused)

	e.llm.Queue(claudetest.Text("tres"))
	if _, err := e.svc.Continue(context.Background(), e.user, first.Conversation, "otra vez"); err != nil {
		t.Fatal(err)
	}
	last := e.llm.Requests()[2]["messages"].([]any)
	if len(last) != 3 {
		t.Errorf("messages = %d, want the failed turn left out", len(last))
	}
}

func TestAConversationHasALimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.llm.Queue(claudetest.Text("hola"))
	first, err := e.svc.Ask(context.Background(), e.user, "uno")
	if err != nil {
		t.Fatal(err)
	}
	for range 39 {
		e.llm.Queue(claudetest.Text("otra"))
		if _, err := e.svc.Continue(context.Background(), e.user, first.Conversation, "otra"); err != nil {
			t.Fatal(err)
		}
	}
	calls := len(e.llm.Requests())

	_, err = e.svc.Continue(context.Background(), e.user, first.Conversation, "una más")

	wantErr(t, err, agents.ErrConversationFull)
	if len(e.llm.Requests()) != calls {
		t.Error("the model was called")
	}
}

func TestAskFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		message string
		reply   *claudetest.Reply
		want    error
	}{
		{name: "blank message", message: "  \n", want: agents.ErrEmptyMessage},
		{name: "refused", message: "hola", reply: ptr(claudetest.Refusal()), want: agents.ErrRefused},
		{name: "api failure", message: "hola", reply: ptr(claudetest.Fail(http.StatusUnauthorized)), want: agents.ErrUnavailable},
		{name: "cut off", message: "hola", reply: ptr(claudetest.Truncated()), want: agents.ErrUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			if tt.reply != nil {
				e.llm.Queue(*tt.reply)
			}
			_, err := e.svc.Ask(context.Background(), e.user, tt.message)
			wantErr(t, err, tt.want)
		})
	}
}

func waitForRequests(t *testing.T, e env, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for len(e.llm.Requests()) < want {
		if time.Now().After(deadline) {
			t.Fatalf("requests = %d, want %d", len(e.llm.Requests()), want)
		}
		time.Sleep(time.Millisecond)
	}
}
