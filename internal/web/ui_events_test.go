package web

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
)

type sseMsg struct {
	Name string
	Data string
}

func (m sseMsg) json(t *testing.T) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(m.Data), &out); err != nil {
		t.Fatalf("event %s data is not JSON: %v (%q)", m.Name, err, m.Data)
	}
	return out
}

type sseStream struct {
	events chan sseMsg
}

const sseWait = 2 * time.Second

// openSSE connects to path on srv as the operator. The response headers are
// written after the broker subscription, so once this returns the stream
// receives every later publish.
func openSSE(t *testing.T, srv *httptest.Server, path string) *sseStream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: testOperatorCookie, Value: testOperatorToken})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d", path, resp.StatusCode)
	}
	st := &sseStream{events: make(chan sseMsg, sseBuf)}
	go func() {
		defer func() { _ = resp.Body.Close() }()
		sc := bufio.NewScanner(resp.Body)
		var cur sseMsg
		var data []string
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if cur.Name != "" {
					cur.Data = strings.Join(data, "\n")
					st.events <- cur
				}
				cur, data = sseMsg{}, nil
			case strings.HasPrefix(line, "event: "):
				cur.Name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				data = append(data, strings.TrimPrefix(line, "data: "))
			}
		}
	}()
	return st
}

func (st *sseStream) next(t *testing.T) sseMsg {
	t.Helper()
	select {
	case m := <-st.events:
		return m
	case <-time.After(sseWait):
		t.Fatal("timed out waiting for an SSE event")
		return sseMsg{}
	}
}

func (st *sseStream) none(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case m := <-st.events:
		t.Fatalf("unexpected event %s %s", m.Name, m.Data)
	case <-time.After(d):
	}
}

func newUIEventServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s, cleanup := newTestServer(t)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(func() {
		srv.Close()
		// Let the debounced queue timer fire before the DB closes.
		time.Sleep(uiQueueDebounce + 100*time.Millisecond)
		cleanup()
	})
	return s, srv
}

const quietWindow = 150 * time.Millisecond

func TestUIEventsScanAndScans(t *testing.T) {
	s, srv := newUIEventServer(t)
	repo := seedUIRepo(t, s.DB, "ev")
	other := seedUIRepo(t, s.DB, "ev-other")
	running := seedUIScan(t, s.DB, repo, db.ScanRunning, "triage")
	done := seedUIScan(t, s.DB, repo, db.ScanDone, "triage")
	otherScan := seedUIScan(t, s.DB, other, db.ScanRunning, "triage")

	all := openSSE(t, srv, "/api/v1/ui/events?events=scan,scans")
	scoped := openSSE(t, srv, "/api/v1/ui/events?repo="+itoa(repo.ID)+"&events=scan")

	s.publishScanRow(&running)
	m := all.next(t)
	payload := m.json(t)
	if m.Name != uiScanEvent || payload["id"] != float64(running.ID) || payload["toast"] != nil {
		t.Fatalf("scan event = %s %v", m.Name, payload)
	}
	if _, ok := payload["log"]; ok {
		t.Fatal("scan event leaked the log")
	}
	if got := scoped.next(t).json(t); got["id"] != float64(running.ID) {
		t.Fatalf("scoped got %v", got["id"])
	}

	s.publishScanRow(&done)
	payload = all.next(t).json(t)
	toast, ok := payload["toast"].(map[string]any)
	if !ok || toast["category"] != successKey {
		t.Fatalf("terminal scan toast = %v", payload["toast"])
	}
	if target := toast["target"].(map[string]any); target["kind"] != "scan" || target["id"] != float64(done.ID) {
		t.Fatalf("toast target = %v", target)
	}
	scoped.next(t)

	s.publishScanRow(&otherScan)
	all.next(t)
	scoped.none(t, quietWindow)

	s.publishScanList(repo.ID)
	m = all.next(t)
	if m.Name != uiScansEvent || m.json(t)["repository_id"] != float64(repo.ID) {
		t.Fatalf("scans event = %s %s", m.Name, m.Data)
	}
	// The scoped client asked only for `scan`.
	scoped.none(t, quietWindow)
}

func TestUIEventsScanLogOffsets(t *testing.T) {
	s, srv := newUIEventServer(t)
	repo := seedUIRepo(t, s.DB, "log")
	sc := seedUIScan(t, s.DB, repo, db.ScanRunning, "triage") // stored log "line one\n" (9 bytes)
	other := seedUIScan(t, s.DB, repo, db.ScanRunning, "triage")
	// The worker flushed this scan's log already, including the line about
	// to be published.
	s.DB.Model(&other).Update("log", "a\nb\n")

	st := openSSE(t, srv, "/api/v1/ui/events?scan="+itoa(sc.ID)+"&events=scan-log")

	s.Broker.Publish(Event{Name: scanLogEvent, ScanID: sc.ID, RepoID: repo.ID, Data: "second\n"})
	s.Broker.Publish(Event{Name: scanLogEvent, ScanID: other.ID, RepoID: repo.ID, Data: "b\n"})
	s.Broker.Publish(Event{Name: scanLogEvent, ScanID: sc.ID, RepoID: repo.ID, Data: "thïrd\n"})

	first := st.next(t).json(t)
	if first["line"] != "second" || first["offset"] != float64(len("line one\nsecond\n")) || first["scan_id"] != float64(sc.ID) {
		t.Fatalf("first = %v", first)
	}
	second := st.next(t).json(t)
	if second["offset"] != float64(len("line one\nsecond\nthïrd\n")) {
		t.Fatalf("offset counts UTF-8 bytes: %v", second)
	}
	st.none(t, quietWindow)
	if off := s.Broker.trackLogOffset(other.ID, "c\n"); off != int64(len("a\nb\nc\n")) {
		t.Fatalf("flushed seed offset = %d", off)
	}

	// A terminal status retires the tracked offset so a resume re-seeds.
	s.DB.Model(&sc).Update("status", db.ScanDone)
	s.publishScanRow(&sc)
	s.Broker.offsetMu.Lock()
	_, tracked := s.Broker.logOffsets[sc.ID]
	s.Broker.offsetMu.Unlock()
	if tracked {
		t.Fatal("offset still tracked after the scan finished")
	}
}

func TestUIEventsFindingScopingAndLegacyIsolation(t *testing.T) {
	s, srv := newUIEventServer(t)
	repo := seedUIRepo(t, s.DB, "f")
	byFinding := openSSE(t, srv, "/api/v1/ui/events?finding=7&events=finding")
	byRepo := openSSE(t, srv, "/api/v1/ui/events?repo="+itoa(repo.ID)+"&events=finding,repository")
	legacy := openSSE(t, srv, "/events")

	s.publishFinding(8, repo.ID, uiChangeUpdated, "assignee")
	s.publishFinding(7, repo.ID, uiChangeUpdated, "status")
	got := byFinding.next(t).json(t)
	if got["id"] != float64(7) || got["change"] != uiChangeUpdated {
		t.Fatalf("finding-scoped = %v", got)
	}
	if fields := got["fields"].([]any); len(fields) != 1 || fields[0] != "status" {
		t.Fatalf("fields = %v", fields)
	}
	byFinding.none(t, quietWindow)
	if a, b := byRepo.next(t).json(t), byRepo.next(t).json(t); a["id"] != float64(8) || b["id"] != float64(7) {
		t.Fatalf("repo-scoped = %v %v", a, b)
	}
	s.publishRepository(repo.ID, uiChangeUpdated)
	if m := byRepo.next(t); m.Name != uiRepositoryEvent {
		t.Fatalf("repository event = %s", m.Name)
	}
	s.publishMeta("labels")
	s.publishSBOM(1, "resolving", 1, 2)
	// The legacy HTML stream never sees JSON-only events.
	legacy.none(t, quietWindow)
	s.publishScanList(0)
	if m := legacy.next(t); m.Name != scanStatusEvent {
		t.Fatalf("legacy got %s", m.Name)
	}
}

func TestUIEventsChatDoneOnSubscribe(t *testing.T) {
	s, srv := newUIEventServer(t)
	repo := seedUIRepo(t, s.DB, "chat")
	conv := db.Conversation{RepositoryID: repo.ID, Title: "t"}
	if err := s.DB.Create(&conv).Error; err != nil {
		t.Fatal(err)
	}
	st := openSSE(t, srv, "/api/v1/ui/events?conv="+itoa(conv.ID))
	m := st.next(t)
	if m.Name != chatDoneEvent || m.json(t)["message"] != nil || m.json(t)["conversation_id"] != float64(conv.ID) {
		t.Fatalf("subscribe chat-done = %s %s", m.Name, m.Data)
	}
	s.DB.Create(&db.ChatMessage{ConversationID: conv.ID, Role: "assistant", Content: "hello"})
	s.Broker.Publish(Event{Name: chatActivityEvent, ConvID: conv.ID, Data: "thinking"})
	s.Broker.Publish(Event{Name: chatDoneEvent, ConvID: conv.ID})
	if got := st.next(t).json(t); got["line"] != "thinking" {
		t.Fatalf("chat-activity = %v", got)
	}
	done := st.next(t).json(t)
	if msg, ok := done["message"].(map[string]any); !ok || msg["content"] != "hello" || msg["role"] != "assistant" {
		t.Fatalf("chat-done = %v", done)
	}
}

func TestUIEventsQueueDebounced(t *testing.T) {
	s, srv := newUIEventServer(t)
	repo := seedUIRepo(t, s.DB, "q")
	sc := seedUIScan(t, s.DB, repo, db.ScanQueued, "triage")
	st := openSSE(t, srv, "/api/v1/ui/events?events=queue")
	for range 5 {
		s.publishScanRow(&sc)
	}
	got := st.next(t).json(t)
	if scans := got["scans"].(map[string]any); scans["queued"] != float64(1) {
		t.Fatalf("queue = %v", got)
	}
	st.none(t, uiQueueDebounce+quietWindow)
}

func TestUIEventsRejectsUnknownEventName(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/events?events=scan-status", nil)),
		http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/events?scan=x", nil)),
		http.StatusBadRequest, uiCodeBadParam)
}

func TestUITestPublish(t *testing.T) {
	s, srv := newUIEventServer(t)
	repo := seedUIRepo(t, s.DB, "tp")
	sc := seedUIScan(t, s.DB, repo, db.ScanDone, "triage")
	st := openSSE(t, srv, "/api/v1/ui/events?repo="+itoa(repo.ID)+"&events=scan,scan-log")

	publish := func(body string) *httptest.ResponseRecorder {
		return serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/_test/publish", body))
	}
	w := publish(`{"event":"scan","scan_id":` + itoa(sc.ID) + `,"payload":{"status":"running"}}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("publish = %d %s", w.Code, w.Body.String())
	}
	got := st.next(t).json(t)
	if got["status"] != "running" || got["id"] != float64(sc.ID) || got["repository"].(map[string]any)["name"] != "tp" {
		t.Fatalf("synthetic scan = %v", got)
	}
	var stored db.Scan
	s.DB.First(&stored, sc.ID)
	if stored.Status != db.ScanDone {
		t.Fatal("test publish wrote to the database")
	}
	w = publish(`{"event":"scan-log","repo_id":` + itoa(repo.ID) + `,"payload":{"scan_id":` + itoa(sc.ID) + `,"line":"x","offset":3}}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("scan-log publish = %d", w.Code)
	}
	if m := st.next(t); m.Name != scanLogEvent || m.json(t)["offset"] != float64(3) {
		t.Fatalf("synthetic scan-log = %s %s", m.Name, m.Data)
	}

	body := requireUIError(t, publish(`{"event":"finding","payload":{"id":1}}`), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	if _, ok := body.Fields["payload.repository_id"]; !ok {
		t.Fatalf("fields = %v", body.Fields)
	}
	requireUIError(t, publish(`{"event":"nope","payload":{}}`), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	requireUIError(t, publish(`{`), http.StatusBadRequest, uiCodeBadParam)
	var queued int64
	s.DB.Model(&db.Scan{}).Where("status = ?", db.ScanQueued).Count(&queued)
	if queued != 0 {
		t.Fatal("test publish enqueued work")
	}
}

func TestUITestPublishDisabledByDefault(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	s.ui.testHooks = false
	w := serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/_test/publish", `{"event":"meta","payload":{"changed":[]}}`))
	requireUIError(t, w, http.StatusNotFound, uiCodeNotFound)
}
