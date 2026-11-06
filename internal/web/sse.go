package web

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"scrutineer/internal/db"
)

// Event is one SSE message. Name maps to the htmx sse-swap attribute;
// Data is the HTML fragment (or plain text) to swap in.
type Event struct {
	Name string // e.g. "scan-log", "scan-status"
	Data string
	// Scoping: which scan/repo/conversation this event is for. Clients
	// subscribe by scan, repo, or conversation; the broker filters.
	ScanID uint
	RepoID uint
	ConvID uint
	// FindingID scopes `finding` events for /api/v1/ui/events subscribers
	// that filter on one finding; the legacy stream never sets it.
	FindingID uint
	// JSON is a pre-built payload for the JSON stream. Events that carry it
	// exist only for /api/v1/ui/events; the legacy HTML stream skips them.
	JSON any
	// Offset is the byte position in scan.log after a scan-log line, filled
	// in by the broker's offset tracker (see Broker.trackLogOffset).
	Offset int64
}

const sseBuf = 64

type client struct {
	ch     chan Event
	scanID uint // 0 = all scans
	repoID uint // 0 = all repos
	convID uint // 0 = all conversations
	// findingID filters on Event.FindingID; 0 = all findings. Only the JSON
	// stream sets it.
	findingID uint
	// names restricts delivery to these event names; nil = every name. A list
	// page only reacts to scan-status, and without this filter it would be sent
	// every log line of every running scan and the whole chat activity stream.
	names map[string]bool
}

// Broker fans SSE events from the worker to connected HTTP clients.
type Broker struct {
	mu      sync.RWMutex
	clients map[*client]struct{}

	// hookMu guards the hooks the web server installs; Publish reads them on
	// every event.
	hookMu sync.RWMutex
	// logSeed returns the stored scan.log for a scan the offset tracker has
	// not seen yet in this process.
	logSeed func(scanID uint) string
	// afterPublish runs after fan-out (the debounced `queue` event and
	// offset bookkeeping on status changes hang off it).
	afterPublish func(Event)

	offsetMu   sync.Mutex
	logOffsets map[uint]int64
}

func NewBroker() *Broker {
	return &Broker{clients: make(map[*client]struct{}), logOffsets: make(map[uint]int64)}
}

// subscription is the full filter set a client can ask for; Subscribe keeps
// its positional signature for the legacy callers.
type subscription struct {
	scanID, repoID, convID, findingID uint
	names                             []string
}

func (b *Broker) Subscribe(scanID, repoID, convID uint, names ...string) *client {
	return b.subscribe(subscription{scanID: scanID, repoID: repoID, convID: convID, names: names})
}

func (b *Broker) subscribe(sub subscription) *client {
	names := sub.names
	c := &client{
		ch:        make(chan Event, sseBuf),
		scanID:    sub.scanID,
		repoID:    sub.repoID,
		convID:    sub.convID,
		findingID: sub.findingID,
	}
	if len(names) > 0 {
		c.names = make(map[string]bool, len(names))
		for _, n := range names {
			c.names[n] = true
		}
	}
	b.mu.Lock()
	b.clients[c] = struct{}{}
	b.mu.Unlock()
	return c
}

func (b *Broker) Unsubscribe(c *client) {
	b.mu.Lock()
	delete(b.clients, c)
	b.mu.Unlock()
}

// Publish sends an event to all matching clients. Non-blocking: slow
// clients get their channel drained.
func (b *Broker) Publish(e Event) {
	if e.Name == scanLogEvent && e.ScanID != 0 {
		e.Offset = b.trackLogOffset(e.ScanID, e.Data)
	}
	b.fanOut(e)
	b.hookMu.RLock()
	after := b.afterPublish
	b.hookMu.RUnlock()
	if after != nil {
		after(e)
	}
}

func (b *Broker) fanOut(e Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for c := range b.clients {
		if c.names != nil && !c.names[e.Name] {
			continue
		}
		if c.scanID != 0 && c.scanID != e.ScanID {
			continue
		}
		if c.repoID != 0 && c.repoID != e.RepoID {
			continue
		}
		if c.convID != 0 && c.convID != e.ConvID {
			continue
		}
		if c.findingID != 0 && c.findingID != e.FindingID {
			continue
		}
		select {
		case c.ch <- e:
		default:
			// Drop if client is backed up
		}
	}
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	scanID, _ := strconv.ParseUint(r.URL.Query().Get("scan"), 10, 64)
	repoID, _ := strconv.ParseUint(r.URL.Query().Get("repo"), 10, 64)
	convID, _ := strconv.ParseUint(r.URL.Query().Get("conv"), 10, 64)

	var names []string
	for name := range strings.SplitSeq(r.URL.Query().Get("events"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}

	c := s.Broker.Subscribe(uint(scanID), uint(repoID), uint(convID), names...)
	defer s.Broker.Unsubscribe(c)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	// Publish only reaches subscribers that already exist, so a chat turn
	// finishing between the page render and this connection would leave the
	// page spinning on a chat-done that is already gone. Re-check the live
	// state now that we are subscribed: the page reloads and picks up the
	// reply it missed.
	if convID != 0 && !s.chatTurnActive(uint(convID)) {
		writeSSEEvent(w, "chat-done", "")
		flusher.Flush()
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-c.ch:
			if e.JSON != nil {
				// JSON-stream-only event (finding, queue, meta, ...); the
				// HTML pages have no swap target for it.
				continue
			}
			var data string
			// A scan-status with no scan ID comes from a bulk action or an
			// enqueue, which name no row to swap: it carries no payload and
			// only tells the list pages to re-fetch their table.
			switch {
			case e.Name != "scan-status":
				data = html.EscapeString(e.Data)
			case e.ScanID != 0:
				data = s.renderScanStatus(e.ScanID)
			}
			writeSSEEvent(w, e.Name, data)
			flusher.Flush()
		}
	}
}

// publishScanRow announces a change to a scan that open pages already hold a
// row for, so the payload can swap that row in place (and toast it once the scan
// finished). Anything that has no single row to point at goes through
// publishScanList instead.
func (s *Server) publishScanRow(scan *db.Scan) {
	s.Broker.Publish(Event{Name: "scan-status", ScanID: scan.ID, RepoID: scan.RepositoryID})
}

// publishScanList tells the list pages that scan rows changed without naming
// one: a bulk action flips many rows at once, and an enqueue adds a row no open
// page has yet, so there is nothing for an OOB row swap to land on. repoID is 0
// for an instance-wide action, which still reaches the unscoped list
// subscribers and deliberately not the per-repository ones.
func (s *Server) publishScanList(repoID uint) {
	s.Broker.Publish(Event{Name: "scan-status", RepoID: repoID})
}

// renderScanStatus loads a scan and renders the OOB row (plus a toast once it
// finished) pushed to repo_show via the scan-status SSE event.
func (s *Server) renderScanStatus(scanID uint) string {
	st, ok := s.scanStatusData(scanID)
	if !ok {
		return ""
	}
	data := map[string]any{"Scan": st.Scan}
	if st.Toast != nil {
		flash := Flash{
			Category:    st.Toast.Category,
			Title:       st.Toast.Title,
			Description: st.Toast.Description,
			Href:        fmt.Sprintf("/scans/%d", st.Scan.ID),
			Label:       st.Toast.Label,
		}
		if st.DisclosureFindingID != 0 {
			flash.Href = fmt.Sprintf("/findings/%d#disclosure", st.DisclosureFindingID)
		}
		data["Flash"] = flash
	}
	var buf strings.Builder
	if err := s.tmpl.ExecuteTemplate(&buf, "scan-status-sse", data); err != nil {
		s.Log.Error("render scan-status-sse", "scan", scanID, "err", err)
		return ""
	}
	return buf.String()
}

// scanStatus is what a scan-status event says about one scan, shared by the
// HTML OOB row and the JSON `scan` event.
type scanStatus struct {
	Scan  db.Scan
	Toast *uiToast
	// DisclosureFindingID is set when the scan drafted a disclosure the
	// operator should review; the toast then targets that finding.
	DisclosureFindingID uint
}

// scanStatusData loads a scan for a scan-status event. Only an outcome is
// worth a toast: a scan reaching `running` pushes a row update like any other
// status, but announcing every start would spam the toaster, and the error
// category would paint it as a failure.
func (s *Server) scanStatusData(scanID uint) (scanStatus, bool) {
	var scan db.Scan
	if err := s.DB.Preload("Repository").First(&scan, scanID).Error; err != nil {
		return scanStatus{}, false
	}
	var n int64
	s.DB.Model(&db.Finding{}).Where("scan_id = ?", scan.ID).Count(&n)
	scan.FindingsCount = int(n)

	st := scanStatus{Scan: scan}
	if !scan.Status.Terminal() {
		return st, true
	}
	cat := successKey
	if scan.Status != db.ScanDone {
		cat = errorKey
	}
	st.Toast = &uiToast{
		Category:    cat,
		Title:       fmt.Sprintf("%s %s", scan.SkillName, scan.Status),
		Description: scan.Repository.Name,
		Label:       "View",
		Target:      &uiTarget{Kind: "scan", ID: scan.ID},
	}
	if findingID := s.disclosureReviewFindingID(scan); findingID != 0 {
		st.DisclosureFindingID = findingID
		st.Toast.Title = "Disclosure draft generated"
		st.Toast.Label = "Review disclosure"
		st.Toast.Target = &uiTarget{Kind: "finding", ID: findingID, Section: "disclosure"}
	}
	return st, true
}

// trackLogOffset returns the byte offset in scan.log after line. Offsets live
// in memory per scan; the first line seen for a scan seeds from the stored
// log. The worker flushes the log to the database in batches, so the stored
// copy may or may not already end with this line: when it does, the line is
// already counted.
func (b *Broker) trackLogOffset(scanID uint, line string) int64 {
	b.offsetMu.Lock()
	defer b.offsetMu.Unlock()
	if off, ok := b.logOffsets[scanID]; ok {
		off += int64(len(line))
		b.logOffsets[scanID] = off
		return off
	}
	b.hookMu.RLock()
	seed := b.logSeed
	b.hookMu.RUnlock()
	var stored string
	if seed != nil {
		stored = seed(scanID)
	}
	off := int64(len(stored))
	if !strings.HasSuffix(stored, line) || line == "" {
		off += int64(len(line))
	}
	b.logOffsets[scanID] = off
	return off
}

// forgetLogOffset drops a scan's tracked offset once it stops producing
// lines (paused or terminal), so a resume re-seeds from the fully flushed log.
func (b *Broker) forgetLogOffset(scanID uint) {
	b.offsetMu.Lock()
	delete(b.logOffsets, scanID)
	b.offsetMu.Unlock()
}

// setHooks installs the server's broker hooks. Safe to call repeatedly.
func (b *Broker) setHooks(logSeed func(uint) string, afterPublish func(Event)) {
	b.hookMu.Lock()
	b.logSeed = logSeed
	b.afterPublish = afterPublish
	b.hookMu.Unlock()
}

// discloseScanGeneratedDraft excludes refused or malformed runs.
func discloseScanGeneratedDraft(scan db.Scan) bool {
	if scan.SkillName != discloseSkillName || scan.FindingID == nil {
		return false
	}
	var result struct {
		GHSA struct {
			Description string `json:"description"`
		} `json:"ghsa"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(scan.Report), &result); err != nil {
		return false
	}
	return strings.TrimSpace(result.Error) == "" && strings.TrimSpace(result.GHSA.Description) != ""
}

// writeSSEEvent emits one SSE event per the spec. Embedded newlines in data
// are expressed as multiple `data:` lines so the browser's EventSource parser
// reconstructs the original text; a single `data: %s` pattern silently drops
// every line after the first newline. EventSource also treats a lone CR as a
// line terminator, so CRs are normalised to LF before splitting: without that
// a repo-controlled filename containing "\revent: ..." would start a new
// protocol field in the browser.
func writeSSEEvent(w io.Writer, name, data string) {
	_, _ = io.WriteString(w, "event: ")
	_, _ = io.WriteString(w, name)
	_, _ = io.WriteString(w, "\n")
	if strings.IndexByte(data, '\r') >= 0 {
		data = strings.ReplaceAll(strings.ReplaceAll(data, "\r\n", "\n"), "\r", "\n")
	}
	for line := range strings.SplitSeq(data, "\n") {
		_, _ = io.WriteString(w, "data: ")
		_, _ = io.WriteString(w, line)
		_, _ = io.WriteString(w, "\n")
	}
	_, _ = io.WriteString(w, "\n")
}
