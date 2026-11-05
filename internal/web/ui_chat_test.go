package web

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"scrutineer/internal/db"
)

// Every chat turn here runs through chatServer's stub runner (chat_test.go):
// no agent, no model call.

type uiConvDetail struct {
	ID           uint             `json:"id"`
	RepositoryID uint             `json:"repository_id"`
	FindingID    *uint            `json:"finding_id"`
	Title        string           `json:"title"`
	Active       bool             `json:"active"`
	Messages     []map[string]any `json:"messages"`
	Back         map[string]any   `json:"back"`
}

func TestUIRepoConversationCreate(t *testing.T) {
	s, done, stub := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	sub := s.Broker.Subscribe(0, repo.ID, 0, uiRepositoryEvent)
	defer s.Broker.Unsubscribe(sub)

	w := serveUI(t, s, operatorReq(t, http.MethodPost, fmt.Sprintf("/api/v1/ui/repositories/%d/conversations", repo.ID),
		map[string]string{"message": "  How does auth work?  "}))
	got := decodeUIJSON[uiConvDetail](t, w, http.StatusCreated)
	if got.RepositoryID != repo.ID || got.FindingID != nil || got.Title == "" || w.Header().Get("ETag") == "" {
		t.Errorf("detail = %+v", got)
	}
	// The stub turn ran synchronously, so the transcript already has the reply.
	if len(got.Messages) != 2 || got.Messages[0]["role"] != db.ChatRoleUser || got.Messages[0]["content"] != "How does auth work?" {
		t.Errorf("messages = %v", got.Messages)
	}
	if stub.gotMsg != "How does auth work?" {
		t.Errorf("runner got %q", stub.gotMsg)
	}
	select {
	case e := <-sub.ch:
		if e.Name != uiRepositoryEvent {
			t.Errorf("event = %s", e.Name)
		}
	case <-time.After(time.Second):
		t.Error("no repository event for the new conversation")
	}
}

func TestUIRepoConversationCreateErrors(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	path := fmt.Sprintf("/api/v1/ui/repositories/%d/conversations", repo.ID)

	body := requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]string{"message": "   "})),
		http.StatusUnprocessableEntity, uiCodeValidationFailed)
	if body.Fields[uiChatMessageField] == "" {
		t.Errorf("fields = %v", body.Fields)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, "{")), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/repositories/999/conversations",
		map[string]string{"message": "hi"})), http.StatusNotFound, uiCodeNotFound)
	s.chatRunner = nil
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]string{"message": "hi"})),
		http.StatusServiceUnavailable, uiCodeUnavailable)
	var n int64
	s.DB.Model(&db.Conversation{}).Count(&n)
	if n != 0 {
		t.Errorf("refused creates left %d conversations", n)
	}
}

func TestUIRepoConversations(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	repoConv, _ := db.CreateConversation(s.DB, repo.ID, nil, "m", "repo chat")
	sc := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone}
	s.DB.Create(&sc)
	f := db.Finding{RepositoryID: repo.ID, ScanID: sc.ID, Title: "f"}
	s.DB.Create(&f)
	if _, err := db.CreateConversation(s.DB, repo.ID, &f.ID, "m", "finding chat"); err != nil {
		t.Fatal(err)
	}

	rows := decodeUIJSON[[]map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodGet,
		fmt.Sprintf("/api/v1/ui/repositories/%d/conversations", repo.ID), nil)), http.StatusOK)
	if len(rows) != 1 || rows[0]["id"].(float64) != float64(repoConv.ID) || rows[0]["active"] != false || rows[0]["finding_id"] != nil {
		t.Errorf("rows = %v", rows)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/repositories/999/conversations", nil)), http.StatusNotFound, uiCodeNotFound)
}

func TestUIConversationDetail(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	conv, _ := db.CreateConversation(s.DB, repo.ID, nil, "m", "hello")
	if _, err := db.AddChatMessage(s.DB, conv.ID, db.ChatRoleUser, "hello"); err != nil {
		t.Fatal(err)
	}
	s.beginChatTurn(conv.ID)

	w := serveUI(t, s, operatorReq(t, http.MethodGet, fmt.Sprintf("/api/v1/ui/conversations/%d", conv.ID), nil))
	got := decodeUIJSON[uiConvDetail](t, w, http.StatusOK)
	if !got.Active || len(got.Messages) != 1 || got.Back[repositoryIDKey].(float64) != float64(repo.ID) || w.Header().Get("ETag") == "" {
		t.Errorf("detail = %+v", got)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/conversations/999", nil)), http.StatusNotFound, uiCodeNotFound)
}

func TestUIConversationMessage(t *testing.T) {
	s, done, stub := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	conv, _ := db.CreateConversation(s.DB, repo.ID, nil, "m", "hello")
	path := fmt.Sprintf("/api/v1/ui/conversations/%d/messages", conv.ID)

	got := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]string{"message": "next?"})), http.StatusAccepted)
	msg := got[uiEventMessageKey].(map[string]any)
	if got["active"] != true || msg["role"] != db.ChatRoleUser || msg["content"] != "next?" || msg["id"] == nil {
		t.Errorf("accepted = %v", got)
	}
	if stub.gotMsg != "next?" {
		t.Errorf("runner got %q", stub.gotMsg)
	}

	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]string{"message": ""})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	s.beginChatTurn(conv.ID)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]string{"message": "again"})), http.StatusConflict, uiCodeInFlight)
	s.endChatTurn(conv.ID)
	s.chatRunner = nil
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]string{"message": "again"})), http.StatusServiceUnavailable, uiCodeUnavailable)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/conversations/999/messages", map[string]string{"message": "x"})), http.StatusNotFound, uiCodeNotFound)
}

func TestUIConversationDelete(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	sc := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone}
	s.DB.Create(&sc)
	f := db.Finding{RepositoryID: repo.ID, ScanID: sc.ID, Title: "f"}
	s.DB.Create(&f)
	conv, _ := db.CreateConversation(s.DB, repo.ID, &f.ID, "m", "hello")
	path := fmt.Sprintf("/api/v1/ui/conversations/%d", conv.ID)
	sub := s.Broker.subscribe(subscription{findingID: f.ID, names: []string{uiFindingEvent}})
	defer s.Broker.Unsubscribe(sub)

	s.beginChatTurn(conv.ID)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodDelete, path, nil)), http.StatusConflict, uiCodeInFlight)
	s.endChatTurn(conv.ID)

	if w := serveUI(t, s, operatorReq(t, http.MethodDelete, path, nil)); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	var n int64
	s.DB.Model(&db.Conversation{}).Count(&n)
	if n != 0 {
		t.Errorf("conversation survived delete")
	}
	select {
	case e := <-sub.ch:
		if fields, _ := e.JSON.(map[string]any)[uiEventFieldsKey].([]string); len(fields) != 1 || fields[0] != "conversations" {
			t.Errorf("finding event = %v", e.JSON)
		}
	case <-time.After(time.Second):
		t.Error("no finding event for the deleted conversation")
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodDelete, path, nil)), http.StatusNotFound, uiCodeNotFound)
}
