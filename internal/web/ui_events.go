package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"scrutineer/internal/db"
)

// JSON server-sent events for the Svelte UI (02-api-plan.md section 4.1). It
// shares the Broker with the legacy HTML stream: legacy events (scan-status,
// scan-log, chat-*) are re-encoded as JSON per subscriber, and the UI-only
// events (finding, repository, sbom, queue, meta) are published with a
// pre-built Event.JSON payload.

const (
	scanStatusEvent   = "scan-status"
	scanLogEvent      = "scan-log"
	chatActivityEvent = "chat-activity"
	chatDoneEvent     = "chat-done"

	uiScanEvent       = "scan"
	uiScansEvent      = "scans"
	uiFindingEvent    = "finding"
	uiRepositoryEvent = "repository"
	uiSBOMEvent       = "sbom"
	uiQueueEvent      = "queue"
	uiMetaEvent       = "meta"

	uiEventPing        = 15 * time.Second
	uiQueueDebounce    = 500 * time.Millisecond
	conversationIDKey  = "conversation_id"
	repositoryIDKey    = "repository_id"
	uiEventChangeKey   = "change"
	uiEventFieldsKey   = "fields"
	uiEventChangedKey  = "changed"
	uiChangeUpdated    = "updated"
	uiChangeCreated    = "created"
	uiChangeDeleted    = "deleted"
	uiEventMessageKey  = "message"
	uiEventLineKey     = "line"
	uiEventOffsetKey   = "offset"
	uiEventScanIDKey   = "scan_id"
	uiEventToastKey    = "toast"
	uiEventPayloadsMax = 1 << 16
)

// uiEventNames is the vocabulary a client may pass in `events=`.
var uiEventNames = map[string]bool{
	uiScanEvent: true, uiScansEvent: true, scanLogEvent: true, uiFindingEvent: true, uiRepositoryEvent: true,
	uiSBOMEvent: true, uiQueueEvent: true, uiMetaEvent: true, chatActivityEvent: true, chatDoneEvent: true,
}

// brokerNamesFor maps requested UI event names to the broker names that
// produce them: `scan` and `scans` both come from scan-status (with and
// without a scan id) or from a pre-built JSON event of the same name.
func brokerNamesFor(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := make([]string, 0, len(names)+1)
	for _, n := range names {
		if n == uiScanEvent || n == uiScansEvent {
			out = append(out, scanStatusEvent)
		}
		out = append(out, n)
	}
	return out
}

type uiEventParams struct {
	sub   subscription
	wants map[string]bool // nil = every name
}

func (p uiEventParams) want(name string) bool { return p.wants == nil || p.wants[name] }

func parseUIEventParams(r *http.Request) (uiEventParams, error) {
	var p uiEventParams
	var err error
	if p.sub.scanID, err = uiQueryID(r, "scan"); err != nil {
		return p, err
	}
	if p.sub.repoID, err = uiQueryID(r, "repo"); err != nil {
		return p, err
	}
	if p.sub.convID, err = uiQueryID(r, "conv"); err != nil {
		return p, err
	}
	if p.sub.findingID, err = uiQueryID(r, "finding"); err != nil {
		return p, err
	}
	var names []string
	for name := range strings.SplitSeq(r.URL.Query().Get("events"), ",") {
		if name = strings.TrimSpace(name); name == "" {
			continue
		}
		if !uiEventNames[name] {
			return p, fmt.Errorf("unknown event %q", name)
		}
		names = append(names, name)
	}
	if len(names) > 0 {
		p.wants = make(map[string]bool, len(names))
		for _, n := range names {
			p.wants[n] = true
		}
	}
	p.sub.names = brokerNamesFor(names)
	return p, nil
}

// uiEvents is GET /api/v1/ui/events.
func (s *Server) uiEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeUIError(w, http.StatusInternalServerError, uiCodeInternal, "streaming not supported", nil)
		return
	}
	p, err := parseUIEventParams(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	c := s.Broker.subscribe(p.sub)
	defer s.Broker.Unsubscribe(c)

	// Long-lived stream: the server's WriteTimeout must not cut it.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set(cacheControlHeader, noStore)
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	// Send a first frame now: some stacks hold the headers until body bytes
	// are written, which would leave EventSource in CONNECTING until the
	// first event or ping.
	_, _ = w.Write([]byte(": connected\n\n"))
	flusher.Flush()

	// Same race fix as the legacy stream: a turn that finished before this
	// subscription existed would otherwise leave the transcript waiting.
	if p.sub.convID != 0 && p.want(chatDoneEvent) && !s.chatTurnActive(p.sub.convID) {
		writeSSEJSON(w, chatDoneEvent, map[string]any{conversationIDKey: p.sub.convID, uiEventMessageKey: nil})
		flusher.Flush()
	}

	ping := time.NewTicker(uiEventPing)
	defer ping.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			_, _ = w.Write([]byte(": ping\n\n"))
			flusher.Flush()
		case e := <-c.ch:
			s.writeUIEvent(w, e, p)
			flusher.Flush()
		}
	}
}

// writeUIEvent encodes one broker event for a JSON subscriber.
func (s *Server) writeUIEvent(w http.ResponseWriter, e Event, p uiEventParams) {
	if e.JSON != nil {
		if p.want(e.Name) {
			writeSSEJSON(w, e.Name, e.JSON)
		}
		return
	}
	switch e.Name {
	case scanStatusEvent:
		s.writeUIScanStatus(w, e, p)
	case scanLogEvent:
		if p.want(scanLogEvent) {
			writeSSEJSON(w, scanLogEvent, map[string]any{
				uiEventScanIDKey: e.ScanID, uiEventLineKey: strings.TrimSuffix(e.Data, "\n"), uiEventOffsetKey: e.Offset,
			})
		}
	case chatActivityEvent:
		if p.want(chatActivityEvent) {
			writeSSEJSON(w, chatActivityEvent, map[string]any{conversationIDKey: e.ConvID, uiEventLineKey: e.Data})
		}
	case chatDoneEvent:
		if p.want(chatDoneEvent) {
			writeSSEJSON(w, chatDoneEvent, map[string]any{conversationIDKey: e.ConvID, uiEventMessageKey: s.lastAssistantMessage(e.ConvID)})
		}
	}
}

// writeUIScanStatus turns a legacy scan-status into `scan` (one row) or
// `scans` (list refetch).
func (s *Server) writeUIScanStatus(w http.ResponseWriter, e Event, p uiEventParams) {
	if e.ScanID == 0 {
		if p.want(uiScansEvent) {
			writeSSEJSON(w, uiScansEvent, map[string]any{repositoryIDKey: e.RepoID})
		}
		return
	}
	if !p.want(uiScanEvent) {
		return
	}
	payload, disclosureFinding, ok := s.uiScanEventPayload(e.ScanID)
	if !ok {
		return
	}
	writeSSEJSON(w, uiScanEvent, payload)
	if disclosureFinding != 0 && p.want(uiFindingEvent) && (p.sub.findingID == 0 || p.sub.findingID == disclosureFinding) {
		writeSSEJSON(w, uiFindingEvent, map[string]any{
			"id": disclosureFinding, repositoryIDKey: e.RepoID, uiEventChangeKey: uiChangeUpdated,
			uiEventFieldsKey: []string{"disclosure_draft"},
		})
	}
}

// uiScanEventPayload is a fresh ScanRow plus the toast for a terminal scan.
// The toast needs the report (disclosure drafts), so only terminal scans pay
// for the full-row load the legacy stream always does.
func (s *Server) uiScanEventPayload(scanID uint) (map[string]any, uint, bool) {
	row, err := s.loadUIScanRow(scanID)
	if err != nil {
		return nil, 0, false
	}
	row[uiEventToastKey] = nil
	var disclosureFinding uint
	if status, _ := row[statusKey].(string); db.ScanStatus(status).Terminal() {
		if st, ok := s.scanStatusData(scanID); ok && st.Toast != nil {
			row[uiEventToastKey] = st.Toast
			disclosureFinding = st.DisclosureFindingID
		}
	}
	return row, disclosureFinding, true
}

// lastAssistantMessage is the chat-done payload's message, nil when none.
func (s *Server) lastAssistantMessage(convID uint) any {
	var msg db.ChatMessage
	err := s.DB.Where("conversation_id = ? AND role = ?", convID, "assistant").Order("id DESC").Limit(1).Find(&msg).Error
	if err != nil || msg.ID == 0 {
		return nil
	}
	return uiChatMessage(msg)
}

func uiChatMessage(m db.ChatMessage) map[string]any {
	return map[string]any{"id": m.ID, "role": m.Role, "content": m.Content, uiKeyCreatedAt: m.CreatedAt}
}

// writeSSEJSON writes one event whose data is a single JSON line.
func writeSSEJSON(w http.ResponseWriter, name string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	writeSSEEvent(w, name, string(b))
}

// ---------------------------------------------------------------- publishers

// publishFinding announces a finding write. fields is the fixed vocabulary of
// changed fields/sub-resources (02 section 4.1); created/deleted pass none.
//
//nolint:unparam // created/deleted callers (finding delete, worker OnFindingCreated) land in later packages
func (s *Server) publishFinding(id, repoID uint, change string, fields ...string) {
	if fields == nil {
		fields = []string{}
	}
	s.Broker.Publish(Event{Name: uiFindingEvent, RepoID: repoID, FindingID: id, JSON: map[string]any{
		"id": id, repositoryIDKey: repoID, uiEventChangeKey: change, uiEventFieldsKey: fields,
	}})
}

// publishRepository announces a repository change.
func (s *Server) publishRepository(id uint, change string) {
	s.Broker.Publish(Event{Name: uiRepositoryEvent, RepoID: id, JSON: map[string]any{"id": id, uiEventChangeKey: change}})
}

// publishSBOM announces SBOM resolution progress.
func (s *Server) publishSBOM(id uint, state string, resolved, total int) {
	s.Broker.Publish(Event{Name: uiSBOMEvent, JSON: map[string]any{"id": id, "state": state, "resolved": resolved, "total": total}})
}

// publishMeta tells the UI to refetch /ui/meta/dynamic.
func (s *Server) publishMeta(changed ...string) {
	s.Broker.Publish(Event{Name: uiMetaEvent, JSON: map[string]any{uiEventChangedKey: changed}})
}

// ---------------------------------------------------------------- broker hooks

// initUIEvents installs the broker hooks the JSON stream relies on: the
// scan-log offset seed and the after-publish bookkeeping.
func (s *Server) initUIEvents() {
	s.Broker.setHooks(s.storedScanLog, s.afterBrokerPublish)
}

func (s *Server) storedScanLog(scanID uint) string {
	var logs []string
	s.DB.Model(&db.Scan{}).Where("id = ?", scanID).Pluck("log", &logs)
	if len(logs) == 0 {
		return ""
	}
	return logs[0]
}

// afterBrokerPublish runs after every event: scan-status schedules the
// debounced queue event and retires the log offset of a scan that stopped.
func (s *Server) afterBrokerPublish(e Event) {
	if e.Name == scanLogEvent && e.JSON == nil {
		s.observeLiveLog(e)
		return
	}
	if e.Name != scanStatusEvent || e.JSON != nil {
		return
	}
	s.scheduleQueueEvent()
	if e.ScanID == 0 {
		return
	}
	var statuses []string
	s.DB.Model(&db.Scan{}).Where("id = ?", e.ScanID).Pluck("status", &statuses)
	if len(statuses) == 0 {
		s.Broker.forgetLogOffset(e.ScanID)
		s.ui.liveLogs.forget(e.ScanID)
		return
	}
	if st := db.ScanStatus(statuses[0]); st.Terminal() || st == db.ScanPaused {
		s.Broker.forgetLogOffset(e.ScanID)
		s.ui.liveLogs.forget(e.ScanID)
	}
}

// scheduleQueueEvent publishes the activity counters once per debounce
// window, however many scan-status events arrive in it.
func (s *Server) scheduleQueueEvent() {
	s.ui.mu.Lock()
	defer s.ui.mu.Unlock()
	if s.ui.queuePending {
		return
	}
	s.ui.queuePending = true
	time.AfterFunc(uiQueueDebounce, func() {
		s.ui.mu.Lock()
		s.ui.queuePending = false
		s.ui.mu.Unlock()
		act, err := s.uiActivity()
		if err != nil {
			return
		}
		s.Broker.Publish(Event{Name: uiQueueEvent, JSON: act})
	})
}

// ---------------------------------------------------------------- test seam

// uiTestPublishRequest is POST /api/v1/ui/_test/publish.
type uiTestPublishRequest struct {
	Event     string         `json:"event"`
	ScanID    uint           `json:"scan_id"`
	RepoID    uint           `json:"repo_id"`
	ConvID    uint           `json:"conv_id"`
	FindingID uint           `json:"finding_id"`
	Payload   map[string]any `json:"payload"`
}

// uiTestPayloadKeys are the keys each event's payload must carry, so a fake
// event is well-formed for the UI's types.
var uiTestPayloadKeys = map[string][]string{
	uiScanEvent:       {"id", repositoryIDKey, statusKey, uiKeyRepository, "actions", uiEventToastKey},
	uiScansEvent:      {repositoryIDKey},
	scanLogEvent:      {uiEventScanIDKey, uiEventLineKey, uiEventOffsetKey},
	uiFindingEvent:    {"id", repositoryIDKey, uiEventChangeKey, uiEventFieldsKey},
	uiRepositoryEvent: {"id", uiEventChangeKey},
	uiSBOMEvent:       {"id", "state", "resolved", "total"},
	uiQueueEvent:      {"scans", uiKeyFindings, "account_paused", "next_account_resume"},
	uiMetaEvent:       {uiEventChangedKey},
	chatActivityEvent: {conversationIDKey, uiEventLineKey},
	chatDoneEvent:     {conversationIDKey, uiEventMessageKey},
}

// uiTestPublish publishes a synthetic event without writing to the database
// or enqueueing anything. It 404s unless test hooks are enabled.
func (s *Server) uiTestPublish(w http.ResponseWriter, r *http.Request) {
	if !s.ui.testHooks {
		uiNotFound(w, "route")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, uiEventPayloadsMax)
	var req uiTestPublishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		uiBadParam(w, "invalid JSON request body")
		return
	}
	required, ok := uiTestPayloadKeys[req.Event]
	if !ok {
		writeUIError(w, http.StatusUnprocessableEntity, uiCodeValidationFailed, "unknown event", map[string]string{"event": "unknown event " + req.Event})
		return
	}
	payload := s.uiTestPayload(req)
	missing := map[string]string{}
	for _, k := range required {
		if _, ok := payload[k]; !ok {
			missing["payload."+k] = "required"
		}
	}
	if len(missing) > 0 {
		writeUIError(w, http.StatusUnprocessableEntity, uiCodeValidationFailed, "payload is missing required keys", missing)
		return
	}
	scanID, repoID, findingID := req.ScanID, req.RepoID, req.FindingID
	if repoID == 0 {
		repoID = payloadID(payload, repositoryIDKey)
	}
	if findingID == 0 && req.Event == uiFindingEvent {
		findingID = payloadID(payload, "id")
	}
	if scanID == 0 && req.Event == scanLogEvent {
		scanID = payloadID(payload, uiEventScanIDKey)
	}
	// fanOut, not Publish: no offset tracking, no queue debounce, no
	// bookkeeping against real scans.
	s.Broker.fanOut(Event{Name: req.Event, ScanID: scanID, RepoID: repoID, ConvID: req.ConvID, FindingID: findingID, JSON: payload})
	w.WriteHeader(http.StatusAccepted)
}

// uiTestPayload fills a `scan` payload from the real row when scan_id names
// one, so a test only states the fields it fakes (e.g. status).
func (s *Server) uiTestPayload(req uiTestPublishRequest) map[string]any {
	payload := req.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	if req.Event != uiScanEvent || req.ScanID == 0 {
		return payload
	}
	row, err := s.loadUIScanRow(req.ScanID)
	if err != nil {
		return payload
	}
	row[uiEventToastKey] = nil
	for k, v := range payload {
		row[k] = v
	}
	return row
}

// payloadID reads a numeric id from a decoded JSON payload; 0 when absent.
func payloadID(payload map[string]any, key string) uint {
	switch v := payload[key].(type) {
	case float64:
		if v > 0 {
			return uint(v)
		}
	case uint:
		return v
	}
	return 0
}
