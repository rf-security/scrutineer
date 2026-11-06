package web

import (
	"net/http"

	"gorm.io/gorm"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

// GET /api/v1/ui/scans: the paged scan list (02 #56), WP-API-0's reference
// list. Scan detail, log, actions and bulk live in WP-API-4's files.

// uiScanStatuses is the set the `status` filter accepts.
var uiScanStatuses = map[string]bool{
	string(db.ScanQueued): true, string(db.ScanRunning): true, string(db.ScanPaused): true, string(db.ScanDone): true,
	string(db.ScanFailed): true, string(db.ScanSkipped): true, string(db.ScanCancelled): true,
}

// uiScanListParams are the parsed filters of GET /ui/scans.
type uiScanListParams struct {
	page         listPage
	skill        scanSkillFilter
	status       string
	completeness string
	group        string
	repositoryID uint
	findingID    uint
	dates        uiDateRange
	sort         string
}

func parseUIScanListParams(r *http.Request) (uiScanListParams, error) {
	var p uiScanListParams
	var err error
	if p.page, err = parseListPage(r); err != nil {
		return p, err
	}
	q := r.URL.Query()
	if p.completeness, err = parseScanCompletenessFilter(q.Get("completeness")); err != nil {
		return p, err
	}
	p.status = q.Get(statusKey)
	if p.status != "" && !uiScanStatuses[p.status] {
		return p, errBadScanStatus(p.status)
	}
	if p.repositoryID, err = uiQueryID(r, "repository_id"); err != nil {
		return p, err
	}
	if p.findingID, err = uiQueryID(r, "finding_id"); err != nil {
		return p, err
	}
	if p.dates, err = parseUIDateRange(q); err != nil {
		return p, err
	}
	p.skill = parseScanSkillFilter(q.Get("skill"))
	p.group = q.Get("group")
	p.sort = q.Get("sort")
	return p, nil
}

type errBadScanStatus string

func (e errBadScanStatus) Error() string { return "invalid status filter " + string(e) }

// where applies every filter except paging and order.
func (p uiScanListParams) where(q *gorm.DB) *gorm.DB {
	q = p.skill.apply(q)
	q = applyScanCompletenessFilter(q, p.completeness)
	if p.status != "" {
		q = q.Where("scans.status = ?", p.status)
	}
	if p.group != "" {
		q = q.Where("scans.scan_group = ?", p.group)
	}
	if p.repositoryID != 0 {
		q = q.Where("scans.repository_id = ?", p.repositoryID)
	}
	if p.findingID != 0 {
		q = q.Where("scans.finding_id = ?", p.findingID)
	}
	return p.dates.apply(q, "scans.created_at")
}

// uiScanListOrder applies the HTML scans page's sort (scansOrder) so URL sort
// tokens are portable between the two lists.
func (s *Server) uiScanListOrder(q *gorm.DB, token string) *gorm.DB {
	q, _, _ = s.scansOrder(q, token)
	return q
}

func (s *Server) uiScanList(w http.ResponseWriter, r *http.Request) {
	p, err := parseUIScanListParams(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	var total int64
	if err := p.where(s.DB.Model(&db.Scan{})).Count(&total).Error; err != nil {
		uiInternal(w, err)
		return
	}
	q := s.uiScanListOrder(p.where(s.DB.Model(&db.Scan{})), p.sort).Limit(p.page.PageSize).Offset(p.page.offset())
	rows, err := s.uiScanRows(q)
	if err != nil {
		uiInternal(w, err)
		return
	}
	writeListWith(w, rows, total, p.page, map[string]any{
		"stats":  s.uiScanStats(),
		"skills": nonNilStrings(s.scanSkillNames()),
		"any":    scanListAny(rows, p.completeness),
	})
}

// uiScanStats is the ScanStats object: queue counters plus runner state.
func (s *Server) uiScanStats() map[string]any {
	stats := s.scanListStats()
	var running int64
	s.DB.Model(&db.Scan{}).Where("status = ?", db.ScanRunning).Count(&running)
	downgraded, overage := false, false
	if s.Worker != nil {
		downgraded, overage = s.Worker.ShouldDowngradeModel(), s.Worker.ShouldPauseOnOverage()
	}
	return map[string]any{
		"running": running, "queued": stats.QueuedCount, "paused": stats.PausedCount,
		"account_paused": stats.AccountPausedCount, "next_account_resume": stats.NextAccountResume,
		"model_downgraded": downgraded, "overage_paused": overage,
	}
}

// scanListAny says which optional columns the page needs, as jobs does.
func scanListAny(rows []map[string]any, completenessFilter string) map[string]bool {
	anySub, anyFocus, anyComplete := false, false, completenessFilter != ""
	for _, row := range rows {
		if v, _ := row["sub_path"].(string); v != "" {
			anySub = true
		}
		if f, ok := row["focus"].(map[string]string); ok && f[uiKeyName] != "" {
			anyFocus = true
		}
		if c, _ := row["completeness"].(string); c == coverage.CompletenessComplete || c == coverage.CompletenessPartial {
			anyComplete = true
		}
	}
	return map[string]bool{"sub_path": anySub, "focus_area": anyFocus, "completeness": anyComplete}
}

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
