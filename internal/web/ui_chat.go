package web

import (
	"errors"
	"net/http"

	"scrutineer/internal/db"
)

// Chat routes of the /api/v1/ui surface (02-api-plan.md #38, #63-#66). They
// wrap the helpers the HTML chat handlers call (chat.go), so the turn guard,
// the runner pool and workspace cleanup are shared. The assistant's reply
// arrives on the `chat-done` SSE event (ui_events.go), never in a response.
//
// The finding-scoped twins (GET/POST /ui/findings/{id}/conversations, #26/#27)
// belong to WP-API-2 and reuse uiConversationRows and uiCreateConversation.

const (
	uiConversationWhat = "conversation"
	uiChatMessageField = "message"
)

// uiConversationRow is the ConversationRow projection.
func (s *Server) uiConversationRow(c db.Conversation) map[string]any {
	return map[string]any{
		"id": c.ID, repositoryIDKey: c.RepositoryID, "finding_id": c.FindingID, uiKeyTitle: c.Title,
		uiKeyModel: c.Model, "active": s.chatTurnActive(c.ID), uiKeyCreatedAt: c.CreatedAt, "updated_at": c.UpdatedAt,
	}
}

// uiConversationRows projects conversations as ConversationRows.
func (s *Server) uiConversationRows(convs []db.Conversation) []map[string]any {
	out := make([]map[string]any, len(convs))
	for i, c := range convs {
		out[i] = s.uiConversationRow(c)
	}
	return out
}

// uiConversationDetailView is ConversationDetail: the row plus the transcript
// and the page the chat belongs to.
func (s *Server) uiConversationDetailView(c *db.Conversation) map[string]any {
	m := s.uiConversationRow(*c)
	msgs := make([]map[string]any, len(c.Messages))
	for i, msg := range c.Messages {
		msgs[i] = uiChatMessage(msg)
	}
	m["messages"] = msgs
	m["back"] = map[string]any{repositoryIDKey: c.RepositoryID, "finding_id": c.FindingID}
	return m
}

// uiChatRequest is the ConversationCreate / ChatMessagePost body.
type uiChatRequest struct {
	Message string `json:"message"`
}

// writeUIChatError maps the chat helpers' refusals: 503 no runner, 422 empty
// message, 409 in_flight while a turn runs, 500 otherwise.
func writeUIChatError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errChatUnavailable):
		writeUIError(w, http.StatusServiceUnavailable, uiCodeUnavailable, err.Error(), nil)
	case errors.Is(err, errChatEmptyMessage):
		writeUIError(w, http.StatusUnprocessableEntity, uiCodeValidationFailed, err.Error(),
			map[string]string{uiChatMessageField: "required"})
	case errors.Is(err, errChatBusy):
		writeUIError(w, http.StatusConflict, uiCodeInFlight, err.Error(), nil)
	default:
		uiInternal(w, err)
	}
}

// publishConversationChange tells the page a conversation belongs to that its
// chat list changed: the finding (fields:["conversations"]) or the repository.
func (s *Server) publishConversationChange(repoID uint, findingID *uint) {
	if findingID != nil {
		s.publishFinding(*findingID, repoID, uiChangeUpdated, "conversations")
		return
	}
	s.publishRepository(repoID, uiChangeUpdated)
}

// uiCreateConversation starts a chat (spending a turn) from a JSON
// {message} body and writes 201 ConversationDetail. The caller has checked
// that the repository (and finding) exist.
func (s *Server) uiCreateConversation(w http.ResponseWriter, r *http.Request, repoID uint, findingID *uint) {
	var req uiChatRequest
	if !decodeUIScanBody(w, r, &req) {
		return
	}
	conv, err := s.createConversation(repoID, findingID, req.Message)
	if err != nil {
		writeUIChatError(w, err)
		return
	}
	s.publishConversationChange(repoID, findingID)
	loaded, err := db.LoadConversation(s.DB, conv.ID)
	if err != nil {
		uiDBError(w, err, uiConversationWhat)
		return
	}
	setETag(w, loaded.UpdatedAt)
	writeUIJSON(w, http.StatusCreated, s.uiConversationDetailView(loaded))
}

// uiRepoExists writes a 404 and returns false when no repository has id.
func (s *Server) uiRepoExists(w http.ResponseWriter, id uint) bool {
	var n int64
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", id).Count(&n).Error; err != nil {
		uiInternal(w, err)
		return false
	}
	if n == 0 {
		uiNotFound(w, "repository")
		return false
	}
	return true
}

// uiRepoConversations is GET /api/v1/ui/repositories/{id}/conversations
// (#38): the repository-wide chats, newest first (capped as the repo page).
func (s *Server) uiRepoConversations(w http.ResponseWriter, r *http.Request) {
	id, ok := uiPathID(w, r, "id")
	if !ok || !s.uiRepoExists(w, id) {
		return
	}
	convs, err := db.ConversationsFor(s.DB, id, nil)
	if err != nil {
		uiInternal(w, err)
		return
	}
	writeUIJSON(w, http.StatusOK, s.uiConversationRows(convs))
}

// uiRepoConversationCreate is POST /api/v1/ui/repositories/{id}/conversations
// (#63). It starts a chat turn, which spends model credits.
func (s *Server) uiRepoConversationCreate(w http.ResponseWriter, r *http.Request) {
	id, ok := uiPathID(w, r, "id")
	if !ok || !s.uiRepoExists(w, id) {
		return
	}
	s.uiCreateConversation(w, r, id, nil)
}

// uiConversationDetail is GET /api/v1/ui/conversations/{id} (#64).
func (s *Server) uiConversationDetail(w http.ResponseWriter, r *http.Request) {
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return
	}
	conv, err := db.LoadConversation(s.DB, id)
	if err != nil {
		uiDBError(w, err, uiConversationWhat)
		return
	}
	setETag(w, conv.UpdatedAt)
	writeUIJSON(w, http.StatusOK, s.uiConversationDetailView(conv))
}

// loadUIConversation loads the conversation row (no messages), writing 404.
func (s *Server) loadUIConversation(w http.ResponseWriter, r *http.Request) (db.Conversation, bool) {
	var conv db.Conversation
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return conv, false
	}
	if err := s.DB.First(&conv, id).Error; err != nil {
		uiDBError(w, err, uiConversationWhat)
		return conv, false
	}
	return conv, true
}

// uiConversationMessage is POST /api/v1/ui/conversations/{id}/messages (#65):
// 202 with the stored user message; the reply arrives on `chat-done`. It
// starts a chat turn, which spends model credits.
func (s *Server) uiConversationMessage(w http.ResponseWriter, r *http.Request) {
	conv, ok := s.loadUIConversation(w, r)
	if !ok {
		return
	}
	var req uiChatRequest
	if !decodeUIScanBody(w, r, &req) {
		return
	}
	msg, err := s.postChatMessage(conv.ID, req.Message)
	if err != nil {
		writeUIChatError(w, err)
		return
	}
	writeUIJSON(w, http.StatusAccepted, map[string]any{uiEventMessageKey: uiChatMessage(*msg), "active": true})
}

// uiConversationDelete is DELETE /api/v1/ui/conversations/{id} (#66): 204,
// or 409 in_flight while a reply is being written.
func (s *Server) uiConversationDelete(w http.ResponseWriter, r *http.Request) {
	conv, ok := s.loadUIConversation(w, r)
	if !ok {
		return
	}
	if err := s.deleteConversation(conv.ID); err != nil {
		writeUIChatError(w, err)
		return
	}
	s.publishConversationChange(conv.RepositoryID, conv.FindingID)
	w.WriteHeader(http.StatusNoContent)
}
