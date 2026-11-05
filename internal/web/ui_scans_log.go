package web

import (
	"strings"
	"sync"
)

// uiLiveLogs mirrors the log of every running scan from its scan-log events,
// in the same byte-offset space the broker stamps on them (Event.Offset).
//
// The worker appends each line to an in-memory buffer, publishes it at once,
// and flushes the buffer to scans.log only every couple of seconds (and only
// when a later line arrives), so the stored log of a running scan trails the
// SSE stream. GET /api/v1/ui/scans/{id}/log serves this mirror while the scan
// runs, which keeps X-Log-Length aligned with the offsets a viewer has already
// seen and lets a gap catch-up (?offset=) return the missing lines instead of
// an empty body. The worker package is not touched: the mirror is rebuilt
// from what the worker already publishes.
type uiLiveLogs struct {
	mu   sync.Mutex
	logs map[uint]*uiLiveLog
}

// uiLiveLog is one scan's mirror. untracked marks a scan whose stored log and
// event offsets could not be aligned (or that outgrew the cap): it is served
// from the database until it stops, without re-reading the log per line.
type uiLiveLog struct {
	buf       strings.Builder
	untracked bool
}

// uiLiveLogMaxBytes caps one mirror. The largest stored log in practice is
// tens of KB; a runaway scan beyond this falls back to the stored log.
const uiLiveLogMaxBytes = 16 << 20

// observe appends a scan-log event's line to its scan's mirror. stored loads
// the database copy and is only called when the mirror is first seeded,
// outside the lock (one scan's lines arrive from one worker goroutine).
func (l *uiLiveLogs) observe(scanID uint, line string, offset int64, stored func(uint) string) {
	if scanID == 0 || l.appendTracked(scanID, line, offset) {
		return
	}
	// First line seen for this scan: seed from the stored log exactly as the
	// broker's offset tracker did, so both agree on where this line ends.
	seed := stored(scanID)
	ll := &uiLiveLog{}
	switch {
	case int64(len(seed)) == offset:
		ll.buf.WriteString(seed)
	case int64(len(seed)+len(line)) == offset:
		ll.buf.WriteString(seed)
		ll.buf.WriteString(line)
	default:
		ll.untracked = true
	}
	if ll.buf.Len() > uiLiveLogMaxBytes {
		ll = &uiLiveLog{untracked: true}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.logs == nil {
		l.logs = make(map[uint]*uiLiveLog)
	}
	if _, raced := l.logs[scanID]; !raced {
		l.logs[scanID] = ll
	}
}

// appendTracked appends line to an existing mirror, reporting whether one
// existed. A line that does not land on its event's offset (or overflows the
// cap) retires the mirror to untracked.
func (l *uiLiveLogs) appendTracked(scanID uint, line string, offset int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	ll, ok := l.logs[scanID]
	if !ok {
		return false
	}
	if ll.untracked {
		return true
	}
	next := ll.buf.Len() + len(line)
	if int64(next) != offset || next > uiLiveLogMaxBytes {
		l.logs[scanID] = &uiLiveLog{untracked: true}
		return true
	}
	ll.buf.WriteString(line)
	return true
}

// snapshot returns the mirrored log of a scan, ok=false when none is tracked.
// The string shares the builder's bytes, which later appends never modify.
func (l *uiLiveLogs) snapshot(scanID uint) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ll, ok := l.logs[scanID]
	if !ok || ll.untracked {
		return "", false
	}
	return ll.buf.String(), true
}

// forget drops a scan's mirror once it stops producing lines (paused or
// terminal); the stored log is complete from then on.
func (l *uiLiveLogs) forget(scanID uint) {
	l.mu.Lock()
	delete(l.logs, scanID)
	l.mu.Unlock()
}

// observeLiveLog is the broker hook feeding s.ui.liveLogs.
func (s *Server) observeLiveLog(e Event) {
	s.ui.liveLogs.observe(e.ScanID, e.Data, e.Offset, s.storedScanLog)
}
