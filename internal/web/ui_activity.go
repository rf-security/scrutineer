package web

import (
	"net/http"
	"time"

	"scrutineer/internal/db"
)

// Activity counters for the nav badges and status bar (02 #8a). The `queue`
// SSE event carries exactly this object.

const failedWindow = 24 * time.Hour

// uiActivity computes the counters with a handful of indexed COUNTs.
func (s *Server) uiActivity() (map[string]any, error) {
	var byStatus []struct {
		Status string
		N      int64
	}
	if err := s.DB.Model(&db.Scan{}).Select("status, COUNT(*) AS n").
		Where("status IN ?", []db.ScanStatus{db.ScanRunning, db.ScanQueued, db.ScanPaused}).
		Group("status").Scan(&byStatus).Error; err != nil {
		return nil, err
	}
	scans := map[string]int64{"running": 0, "queued": 0, "paused": 0, "failed_24h": 0}
	for _, row := range byStatus {
		scans[row.Status] = row.N
	}
	var failed int64
	s.DB.Model(&db.Scan{}).Where("status = ? AND finished_at >= ?", db.ScanFailed, time.Now().Add(-failedWindow)).Count(&failed)
	scans["failed_24h"] = failed

	var open, fresh int64
	s.DB.Model(&db.Finding{}).Where("status NOT IN ?", db.ClosedFindingLifecycles).Count(&open)
	s.DB.Model(&db.Finding{}).Where("status = ?", db.FindingNew).Count(&fresh)

	stats := s.scanListStats()
	return map[string]any{
		"scans":               scans,
		uiKeyFindings:         map[string]int64{"open": open, "new": fresh},
		"account_paused":      stats.AccountPausedCount > 0,
		"next_account_resume": stats.NextAccountResume,
	}, nil
}

func (s *Server) uiActivityHandler(w http.ResponseWriter, _ *http.Request) {
	act, err := s.uiActivity()
	if err != nil {
		uiInternal(w, err)
		return
	}
	writeUIJSON(w, http.StatusOK, act)
}
