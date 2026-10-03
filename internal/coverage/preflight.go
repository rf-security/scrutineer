package coverage

import (
	"strings"
	"time"
)

// BackendProbe contains sanitized evidence from a bounded live model request.
type BackendProbe struct {
	ProbeID          string     `json:"probe_id"`
	ReceiptID        uint       `json:"receipt_id,omitempty"`
	ConfigHash       string     `json:"config_hash"`
	Status           string     `json:"status"`
	Error            string     `json:"error,omitempty"`
	RateLimited      bool       `json:"rate_limited,omitempty"`
	RateLimitResetAt *time.Time `json:"rate_limit_reset_at,omitempty"`
	CheckedAt        time.Time  `json:"checked_at"`
	ExpiresAt        time.Time  `json:"expires_at"`
	Reused           bool       `json:"reused"`
	CostUSD          float64    `json:"cost_usd"`
	InputTokens      int        `json:"input_tokens"`
	OutputTokens     int        `json:"output_tokens"`
	CacheReadTokens  int        `json:"cache_read_tokens,omitempty"`
	CacheWriteTokens int        `json:"cache_write_tokens,omitempty"`
}

const (
	PreflightReady    = "ready"
	PreflightDegraded = "degraded"
	PreflightBlocked  = "blocked"
)

// Preflight is worker-owned evidence, not part of the skill's coverage claim.
// Missing entries are namespaced as command:<name> or feature:<name>.
type Preflight struct {
	Status   string   `json:"status"`
	Missing  []string `json:"missing"`
	Degraded bool     `json:"degraded"`
	// Error means the probe itself failed; degraded mode cannot waive it.
	Error   string        `json:"error,omitempty"`
	Backend *BackendProbe `json:"backend,omitempty"`
}

// CapPreflight must also run after reconciliation so model receipts cannot
// turn known runtime shortfalls into a claim of complete coverage.
func (rec *Record) CapPreflight() {
	if rec.Preflight != nil && rec.Preflight.Backend != nil && rec.Preflight.Backend.Status != PreflightReady {
		rec.Completeness = CompletenessPartial
		rec.Reason = "backend preflight blocked: " + rec.Preflight.Backend.Error
		return
	}
	if rec.Preflight == nil || rec.Preflight.Status == PreflightReady {
		return
	}
	rec.Completeness = CompletenessPartial
	rec.Reason = "capability preflight " + rec.Preflight.Status
	if len(rec.Preflight.Missing) > 0 {
		rec.Reason += ": " + strings.Join(rec.Preflight.Missing, ", ")
	}
	if rec.Preflight.Error != "" {
		rec.Reason += ": " + rec.Preflight.Error
	}
}
