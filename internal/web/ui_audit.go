package web

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"scrutineer/internal/db"
)

// GET /api/v1/ui/audit (02-api-plan.md #62): the audit queue as FindingRows
// and the agreement metrics in snake_case, replacing the PascalCase
// /api/v1/audit/{queue,metrics} payloads for the UI.

// parseUIAuditParams reads limit (1..500, default db.AuditQueue's 50) and
// since (RFC 3339). Unlike the export route, bad values are a 400 rather than
// silently ignored.
func parseUIAuditParams(r *http.Request) (db.AuditQueueOptions, error) {
	var opts db.AuditQueueOptions
	q := r.URL.Query()
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > auditMaxLimit {
			return opts, fmt.Errorf("limit must be 1..%d, got %q", auditMaxLimit, v)
		}
		opts.Limit = n
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return opts, fmt.Errorf("since must be an RFC 3339 time, got %q", v)
		}
		opts.Since = t
	}
	return opts, nil
}

// uiAuditMetrics is the snake_case AuditMetrics.
func uiAuditMetrics(m db.AuditMetrics) map[string]any {
	byVerdict := m.ByVerdict
	if byVerdict == nil {
		byVerdict = map[string]int64{}
	}
	const pct = 100
	return map[string]any{
		"total_reviews":          m.TotalReviews,
		"with_automated_outcome": m.WithAutomatedOutcome,
		"agreements":             m.Agreements,
		"agreement_rate":         m.AgreementRate,
		"agreement_pct":          int(m.AgreementRate * pct),
		"by_verdict":             byVerdict,
	}
}

func (s *Server) uiAudit(w http.ResponseWriter, r *http.Request) {
	opts, err := parseUIAuditParams(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	rows, err := db.AuditQueue(s.DB, opts)
	if err != nil {
		uiInternal(w, err)
		return
	}
	metrics, err := db.ComputeAuditMetrics(s.DB)
	if err != nil {
		uiInternal(w, err)
		return
	}
	writeUIJSON(w, http.StatusOK, map[string]any{
		"queue":          s.uiFindingRows(rows),
		"metrics":        uiAuditMetrics(metrics),
		"verdict_labels": auditVerdictLabels,
		"exports": map[string]any{
			"queue_json": map[string]string{uiKeyURL: "/api/v1/audit/queue", "filename": "audit-queue.json"},
		},
	})
}
