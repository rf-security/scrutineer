package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
	"scrutineer/internal/worker"
)

// chatTurnRunner runs one chat turn. *worker.ChatRunner satisfies it in
// production; tests substitute a stub so handler behaviour can be exercised
// without a real agent.
type chatTurnRunner interface {
	RunTurn(ctx context.Context, conv *db.Conversation, userMessage string, emit func(worker.Event)) (worker.ChatTurnResult, error)
}

// chatTurnTimeout bounds a single background chat turn so a stuck agent can't
// pin a workspace forever.
const chatTurnTimeout = 15 * time.Minute

// chatSlotsPerScanSlot divides the queue's concurrency to size the chat pool.
// The pool is separate from the queue's, so chat turns add to the scan ceiling
// instead of competing for it: at full concurrency the host runs N scan
// containers plus this many chat containers, and halving keeps that total at
// 1.5N rather than 2N.
const chatSlotsPerScanSlot = 2

// chatTurnSlots sizes the concurrent-chat-turn pool from the queue's
// concurrency. A server built without a queue, or one reporting no concurrency
// at all, still gets one slot, since a zero-capacity channel would block every
// turn forever.
func chatTurnSlots(q *queue.Queue) int {
	if q == nil {
		return 1
	}
	return max(1, q.Concurrency()/chatSlotsPerScanSlot)
}

// conversationCreateRepo starts a repo-wide chat from the repository page.
func (s *Server) conversationCreateRepo(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	s.startConversation(w, r, repo.ID, nil, fmt.Sprintf("/repositories/%d", repo.ID))
}

// conversationCreateFinding starts a finding-scoped chat from the finding page.
func (s *Server) conversationCreateFinding(w http.ResponseWriter, r *http.Request) {
	f, ok := loadByID[db.Finding](s, w, r)
	if !ok {
		return
	}
	backTo := fmt.Sprintf("/findings/%d", f.ID)
	repoID, err := s.findingChatRepoID(f)
	if err != nil {
		setFlash(w, Flash{Category: errorKey, Title: "Chat unavailable", Description: "Could not resolve which repository this finding belongs to."})
		s.redirect(w, r, backTo)
		return
	}
	fid := f.ID
	s.startConversation(w, r, repoID, &fid, backTo)
}

// findingChatRepoID is the repository a finding-scoped chat belongs to.
// Legacy rows may not have the denormalized repository_id; fall back to the
// producing scan, mirroring findingShow.
func (s *Server) findingChatRepoID(f db.Finding) (uint, error) {
	if f.RepositoryID != 0 {
		return f.RepositoryID, nil
	}
	var scan db.Scan
	if err := s.DB.First(&scan, f.ScanID).Error; err != nil {
		s.Log.Error("chat: load finding scan", "finding", f.ID, "scan", f.ScanID, "err", err)
		return 0, err
	}
	return scan.RepositoryID, nil
}

// Chat refusals shared by the HTML handlers (which flash them) and the
// /api/v1/ui chat routes (which map them to statuses).
var (
	errChatUnavailable  = errors.New("chat unavailable: no agent runner is configured")
	errChatEmptyMessage = errors.New("message is empty")
	errChatBusy         = errors.New("still thinking: wait for the current reply")
	errChatCreate       = errors.New("the conversation could not be created")
	errChatPersist      = errors.New("the message could not be saved")
)

// startConversation creates a conversation from the first message, persists that
// message, kicks off the opening turn, and sends the analyst to the chat page.
func (s *Server) startConversation(w http.ResponseWriter, r *http.Request, repoID uint, findingID *uint, backTo string) {
	conv, err := s.createConversation(repoID, findingID, r.FormValue("message"))
	if err != nil {
		var f Flash
		switch {
		case errors.Is(err, errChatUnavailable):
			f = Flash{Category: errorKey, Title: "Chat unavailable", Description: "No agent runner is configured."}
		case errors.Is(err, errChatEmptyMessage):
			f = Flash{Category: errorKey, Title: "Empty message", Description: "Type a message to start the conversation."}
		case errors.Is(err, errChatPersist):
			f = Flash{Category: errorKey, Title: "Chat unavailable", Description: "The message could not be saved."}
		default:
			f = Flash{Category: errorKey, Title: "Chat unavailable", Description: "The conversation could not be created."}
		}
		setFlash(w, f)
		s.redirect(w, r, backTo)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/conversations/%d", conv.ID))
}

// createConversation creates a conversation from the first message, persists
// that message and kicks off the opening turn. Shared by the HTML create
// handlers and the /api/v1/ui create routes.
func (s *Server) createConversation(repoID uint, findingID *uint, message string) (*db.Conversation, error) {
	if s.chatRunner == nil {
		return nil, errChatUnavailable
	}
	message = strings.TrimSpace(message)
	if message == "" {
		return nil, errChatEmptyMessage
	}
	conv, err := db.CreateConversation(s.DB, repoID, findingID, s.DefaultModel(), message)
	if err != nil {
		s.Log.Error("chat: create conversation", "repo", repoID, "err", err)
		return nil, errChatCreate
	}
	if _, err := db.AddChatMessage(s.DB, conv.ID, db.ChatRoleUser, message); err != nil {
		// The conversation row is already committed; drop it rather than leave
		// a titled, message-less chat in the panel.
		s.Log.Error("chat: persist first message", "conv", conv.ID, "err", err)
		s.DB.Delete(&db.Conversation{}, conv.ID)
		return nil, errChatPersist
	}
	s.beginChatTurn(conv.ID)
	s.spawnTurn(conv.ID, message)
	return conv, nil
}

// conversationShow renders the full chat page.
func (s *Server) conversationShow(w http.ResponseWriter, r *http.Request) {
	conv, ok := s.loadConversation(w, r)
	if !ok {
		return
	}
	var findingID uint
	if conv.FindingID != nil {
		findingID = *conv.FindingID
	}
	title := conv.Title
	if title == "" {
		title = "Chat"
	}
	s.render(w, r, "conversation_show.html", map[string]any{
		pageTitleKey: title,
		"Conv":       conv,
		"Active":     s.chatTurnActive(conv.ID),
		"BackHref":   conversationBackHref(conv),
		"FindingID":  findingID,
	})
}

// conversationMessage appends the analyst's message and runs the next turn. It
// refuses while a turn is already in flight so the two can't interleave on the
// same session.
func (s *Server) conversationMessage(w http.ResponseWriter, r *http.Request) {
	conv, ok := loadByID[db.Conversation](s, w, r)
	if !ok {
		return
	}
	dest := fmt.Sprintf("/conversations/%d", conv.ID)
	if _, err := s.postChatMessage(conv.ID, r.FormValue("message")); err != nil {
		var f Flash
		switch {
		case errors.Is(err, errChatEmptyMessage):
			f = Flash{Category: errorKey, Title: "Empty message", Description: "Type a message to send."}
		case errors.Is(err, errChatUnavailable):
			f = Flash{Category: errorKey, Title: "Chat unavailable", Description: "No agent runner is configured."}
		case errors.Is(err, errChatBusy):
			f = Flash{Category: errorKey, Title: "Still thinking", Description: "Wait for the current reply before sending another message."}
		default:
			f = Flash{Category: errorKey, Title: "Chat unavailable", Description: "The message could not be saved."}
		}
		setFlash(w, f)
	}
	s.redirect(w, r, dest)
}

// postChatMessage persists the analyst's message and starts the next turn,
// returning the stored message. Shared by the HTML form and
// POST /api/v1/ui/conversations/{id}/messages.
func (s *Server) postChatMessage(convID uint, message string) (*db.ChatMessage, error) {
	message = strings.TrimSpace(message)
	if message == "" {
		return nil, errChatEmptyMessage
	}
	if s.chatRunner == nil {
		return nil, errChatUnavailable
	}
	if !s.beginChatTurn(convID) {
		return nil, errChatBusy
	}
	msg, err := db.AddChatMessage(s.DB, convID, db.ChatRoleUser, message)
	if err != nil {
		s.endChatTurn(convID)
		s.Log.Error("chat: persist message", "conv", convID, "err", err)
		return nil, errChatPersist
	}
	s.spawnTurn(convID, message)
	return msg, nil
}

// conversationDelete drops a conversation, its messages and its on-disk
// workspace, which is a full clone plus the harness state dir and is otherwise
// only reclaimed when the whole repository is deleted. Refused while a turn is
// in flight: the agent is still reading the clone this would remove under it.
func (s *Server) conversationDelete(w http.ResponseWriter, r *http.Request) {
	conv, ok := loadByID[db.Conversation](s, w, r)
	if !ok {
		return
	}
	if err := s.deleteConversation(conv.ID); err != nil {
		if errors.Is(err, errChatBusy) {
			setFlash(w, Flash{Category: errorKey, Title: "Still thinking",
				Description: "Wait for the current reply before deleting this conversation."})
			s.redirect(w, r, fmt.Sprintf("/conversations/%d", conv.ID))
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	setFlash(w, Flash{Category: "success", Title: "Conversation deleted",
		Description: "The transcript and its working copy of the clone were removed."})
	s.redirect(w, r, conversationBackHref(&conv))
}

// deleteConversation removes a conversation and its workspace, refusing with
// errChatBusy while a turn runs. Shared by the HTML delete form and
// DELETE /api/v1/ui/conversations/{id}.
func (s *Server) deleteConversation(convID uint) error {
	// Claiming the slot rather than just reading it, so no turn can start
	// between the check and the removal either.
	if !s.beginChatTurn(convID) {
		return errChatBusy
	}
	defer s.endChatTurn(convID)
	if err := db.DeleteConversation(s.DB, convID); err != nil {
		s.Log.Error("chat: delete conversation", "conv", convID, "err", err)
		return err
	}
	// After the commit, so a failed transaction never strands a live
	// conversation whose workspace is already gone.
	if err := s.Worker.RemoveChatArtifacts(convID); err != nil {
		s.Log.Error("chat: remove chat workspace", "conv", convID, "err", err)
	}
	return nil
}

// runChatTurn executes one turn in the background: it streams activity to the
// conversation's SSE subscribers, persists the assistant reply and the session
// to resume next time, then signals completion so the page reloads the clean
// transcript.
func (s *Server) runChatTurn(convID uint, message string) {
	defer s.Broker.Publish(Event{Name: "chat-done", ConvID: convID})
	defer s.endChatTurn(convID)

	// A chat turn spawns the same agent (and container) a scan does, so it
	// takes a slot from a pool sized like the worker's rather than running
	// unbounded from an HTTP-triggered goroutine.
	s.chatSlots <- struct{}{}
	defer func() { <-s.chatSlots }()

	ctx, cancel := context.WithTimeout(context.Background(), chatTurnTimeout)
	defer cancel()

	conv, err := db.LoadConversation(s.DB, convID)
	if err != nil {
		s.Log.Error("chat: load conversation", "conv", convID, "err", err)
		return
	}
	emit := func(e worker.Event) {
		s.Broker.Publish(Event{Name: "chat-activity", Data: worker.FormatEvent(e), ConvID: convID})
	}
	res, err := s.chatRunner.RunTurn(ctx, conv, message, emit)
	// The session is recorded even when the turn failed: a resume that forked
	// a new session before dying must be carried forward, or the next turn
	// resumes the stale id and this turn's message never reaches the model. An
	// empty id means "nothing new to record", never "forget the session".
	if res.SessionID != "" {
		if serr := db.SetConversationSession(s.DB, convID, res.SessionID, res.Backend); serr != nil {
			s.Log.Error("chat: persist session", "conv", convID, "err", serr)
		}
	}
	reply := res.Response
	if err != nil {
		s.Log.Warn("chat turn failed", "conv", convID, "err", err)
		// A turn that hit the turn cap or the timeout has usually already
		// produced the answer; keep it and note the failure underneath rather
		// than replacing a good reply with the error alone.
		note := "The assistant could not complete this turn: " + err.Error()
		if strings.TrimSpace(reply) == "" {
			reply = note
		} else {
			reply += "\n\n_" + note + "_"
		}
	}
	if _, err := db.AddChatMessage(s.DB, convID, db.ChatRoleAssistant, reply); err != nil {
		s.Log.Error("chat: persist assistant message", "conv", convID, "err", err)
	}
}

// beginChatTurn marks a conversation busy, returning false if a turn is already
// running for it.
func (s *Server) beginChatTurn(convID uint) bool {
	s.chatMu.Lock()
	defer s.chatMu.Unlock()
	if _, active := s.chatActive[convID]; active {
		return false
	}
	s.chatActive[convID] = struct{}{}
	return true
}

func (s *Server) endChatTurn(convID uint) {
	s.chatMu.Lock()
	delete(s.chatActive, convID)
	s.chatMu.Unlock()
}

func (s *Server) chatTurnActive(convID uint) bool {
	s.chatMu.Lock()
	defer s.chatMu.Unlock()
	_, active := s.chatActive[convID]
	return active
}

func (s *Server) loadConversation(w http.ResponseWriter, r *http.Request) (*db.Conversation, bool) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return nil, false
	}
	conv, err := db.LoadConversation(s.DB, uint(id))
	if err != nil {
		http.NotFound(w, r)
		return nil, false
	}
	return conv, true
}

// conversationBackHref links a conversation back to the page it belongs to: the
// finding for a finding-scoped chat, the repository otherwise.
func conversationBackHref(conv *db.Conversation) string {
	if conv.FindingID != nil {
		return fmt.Sprintf("/findings/%d", *conv.FindingID)
	}
	return fmt.Sprintf("/repositories/%d", conv.RepositoryID)
}
