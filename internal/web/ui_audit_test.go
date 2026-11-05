package web

import (
	"net/http"
	"testing"

	"scrutineer/internal/db"
)

func TestUIAudit(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "audit")
	sc := seedUIScan(t, s.DB, repo, db.ScanDone, "x")
	low := seedUIFinding(t, s.DB, sc, "Low one", db.FindingNew)
	s.DB.Model(&low).Update("severity", "Low")
	seedUIFinding(t, s.DB, sc, "High one", db.FindingNew) // not in the queue

	type auditView struct {
		Queue         []map[string]any `json:"queue"`
		Metrics       map[string]any   `json:"metrics"`
		VerdictLabels []string         `json:"verdict_labels"`
		Exports       map[string]any   `json:"exports"`
	}
	got := decodeUIJSON[auditView](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/audit", nil)), http.StatusOK)
	if len(got.Queue) != 1 || got.Queue[0]["id"].(float64) != float64(low.ID) || got.Queue[0]["updated_at"] == nil ||
		got.Queue[0]["repository"].(map[string]any)[uiKeyName] != repo.Name {
		t.Fatalf("queue = %v", got.Queue)
	}
	for _, k := range []string{"total_reviews", "with_automated_outcome", "agreements", "agreement_rate", "agreement_pct", "by_verdict"} {
		if _, ok := got.Metrics[k]; !ok {
			t.Errorf("metrics missing %s: %v", k, got.Metrics)
		}
	}
	if len(got.VerdictLabels) != 4 || got.VerdictLabels[0] != "true_positive" {
		t.Errorf("verdict_labels = %v", got.VerdictLabels)
	}
	if got.Exports["queue_json"].(map[string]any)["url"] != "/api/v1/audit/queue" {
		t.Errorf("exports = %v", got.Exports)
	}

	got = decodeUIJSON[auditView](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/audit?since=2999-01-01T00:00:00Z", nil)), http.StatusOK)
	if len(got.Queue) != 0 {
		t.Errorf("since in the future: %d rows", len(got.Queue))
	}
	for _, q := range []string{"limit=0", "limit=501", "limit=x", "since=yesterday"} {
		requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/audit?"+q, nil)), http.StatusBadRequest, uiCodeBadParam)
	}
}
