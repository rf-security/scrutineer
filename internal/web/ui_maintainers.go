package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// Maintainers on the /api/v1/ui surface (02-api-plan.md #70-#72,
// F-MAINT-01/02).

// maintainerOpenFindingCountSQL is maintainerFindingCountSQL without the
// closed lifecycles: the number every other count shows. finding_count keeps
// the HTML index's meaning (closed included).
var maintainerOpenFindingCountSQL = `(
	SELECT COUNT(f.id)
	FROM repository_maintainers rm_count
	JOIN findings f ON f.repository_id = rm_count.repository_id
	LEFT JOIN scans s ON s.id = f.scan_id
	WHERE rm_count.maintainer_id = maintainers.id
	  AND f.status NOT IN (` + db.ClosedFindingLifecycleSQLValues() + `)
	  AND ` + aliasedFindingsScanFilter + `
)`

// uiMaintainerRowSelect is maintainerListSelect plus the open count.
var uiMaintainerRowSelect = maintainerListSelect + ", " + maintainerOpenFindingCountSQL + " AS open_finding_count"

// uiMaintainerListRow is one maintainer with its counts.
type uiMaintainerListRow struct {
	db.Maintainer
	RepositoryCount  int `gorm:"column:repository_count"`
	FindingCount     int `gorm:"column:finding_count"`
	OpenFindingCount int `gorm:"column:open_finding_count"`
}

// uiMaintainerStatuses is the set the `status` filter accepts.
var uiMaintainerStatuses = map[string]bool{
	string(db.MaintainerActive): true, string(db.MaintainerInactive): true, string(db.MaintainerUnknown): true,
}

// uiMaintainerRow is the UIMaintainer projection.
func uiMaintainerRow(m uiMaintainerListRow) map[string]any {
	return map[string]any{
		"id":                 m.ID,
		"login":              m.Login,
		uiKeyName:            m.Name,
		"email":              m.Email,
		"company":            m.Company,
		"avatar_url":         m.AvatarURL,
		statusKey:            string(m.Status),
		"notes":              m.Notes,
		"do_not_contact":     m.DoNotContact,
		"repository_count":   m.RepositoryCount,
		"finding_count":      m.FindingCount,
		"open_finding_count": m.OpenFindingCount,
		uiKeyCreatedAt:       m.CreatedAt,
		"updated_at":         m.UpdatedAt,
	}
}

// maintainerPage writes a UIMaintainer page of q; order is applied after the
// count.
func (s *Server) maintainerPage(w http.ResponseWriter, p listPage, q func() *gorm.DB, order func(*gorm.DB) *gorm.DB) {
	var total int64
	if err := q().Count(&total).Error; err != nil {
		uiInternal(w, err)
		return
	}
	var rows []uiMaintainerListRow
	if err := order(q()).Select(uiMaintainerRowSelect).Limit(p.PageSize).Offset(p.offset()).Scan(&rows).Error; err != nil {
		uiInternal(w, err)
		return
	}
	items := make([]map[string]any, len(rows))
	for i, row := range rows {
		items[i] = uiMaintainerRow(row)
	}
	writeList(w, items, total, p)
}

// loadUIMaintainer loads one maintainer with its counts.
func (s *Server) loadUIMaintainer(id uint) (uiMaintainerListRow, error) {
	var rows []uiMaintainerListRow
	if err := s.DB.Model(&db.Maintainer{}).Select(uiMaintainerRowSelect).Where("maintainers.id = ?", id).
		Limit(1).Scan(&rows).Error; err != nil {
		return uiMaintainerListRow{}, err
	}
	if len(rows) == 0 {
		return uiMaintainerListRow{}, gorm.ErrRecordNotFound
	}
	return rows[0], nil
}

// GET /ui/maintainers
func (s *Server) uiMaintainerList(w http.ResponseWriter, r *http.Request) {
	p, err := parseListPage(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	status := r.URL.Query().Get(statusKey)
	if status != "" && !uiMaintainerStatuses[status] {
		uiBadParam(w, fmt.Sprintf("invalid status filter %q", status))
		return
	}
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	token := r.URL.Query().Get("sort")
	q := func() *gorm.DB { return maintainersFilter(s.DB.Model(&db.Maintainer{}), status, search) }
	s.maintainerPage(w, p, q, func(q *gorm.DB) *gorm.DB {
		q, _ = maintainersOrder(q, token)
		return q
	})
}

// GET /ui/maintainers/{id}
func (s *Server) uiMaintainerShow(w http.ResponseWriter, r *http.Request) {
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return
	}
	m, err := s.loadUIMaintainer(id)
	if err != nil {
		uiDBError(w, err, "maintainer")
		return
	}
	setETag(w, m.UpdatedAt)
	writeUIJSON(w, http.StatusOK, uiMaintainerRow(m))
}

// uiMaintainerPatchBody is the PATCH /ui/maintainers/{id} body.
type uiMaintainerPatchBody struct {
	DoNotContact *bool `json:"do_not_contact"`
}

// errMaintainerChanged reports a lost If-Match race on the conditional update.
var errMaintainerChanged = errors.New("maintainer changed since you loaded it")

// PATCH /ui/maintainers/{id}: sets do_not_contact (maintainerDoNotContact's
// JSON twin), versioned by If-Match on updated_at.
func (s *Server) uiMaintainerPatch(w http.ResponseWriter, r *http.Request) {
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return
	}
	var body uiMaintainerPatchBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, apiMaxBody)).Decode(&body); err != nil {
		uiBadParam(w, "invalid JSON request body")
		return
	}
	if body.DoNotContact == nil {
		writeUIFields(w, uiFieldErrors{"do_not_contact": "required"})
		return
	}
	m, err := s.loadUIMaintainer(id)
	if err != nil {
		uiDBError(w, err, "maintainer")
		return
	}
	if !checkIfMatch(w, r, m.UpdatedAt, uiMaintainerRow(m)) {
		return
	}
	if err := s.setMaintainerDoNotContact(m.Maintainer, *body.DoNotContact); err != nil {
		if errors.Is(err, errMaintainerChanged) {
			current, _ := s.loadUIMaintainer(id)
			writeUIErrorExtra(w, http.StatusConflict, uiCodeConflict, err.Error(), map[string]any{"current": uiMaintainerRow(current)})
			return
		}
		uiInternal(w, err)
		return
	}
	m, err = s.loadUIMaintainer(id)
	if err != nil {
		uiDBError(w, err, "maintainer")
		return
	}
	setETag(w, m.UpdatedAt)
	writeUIJSON(w, http.StatusOK, uiMaintainerRow(m))
}

// setMaintainerDoNotContact writes the flag only if the row still carries
// the updated_at it was loaded with, so a concurrent write is a conflict.
func (s *Server) setMaintainerDoNotContact(m db.Maintainer, value bool) error {
	res := s.DB.Model(&db.Maintainer{}).Where("id = ? AND updated_at = ?", m.ID, m.UpdatedAt).
		Update("do_not_contact", value)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errMaintainerChanged
	}
	return nil
}

// uiMaintainerRepoIDs selects the repositories a maintainer is linked to.
func (s *Server) uiMaintainerRepoIDs(id uint) *gorm.DB {
	return s.DB.Table("repository_maintainers").Select("repository_id").Where("maintainer_id = ?", id)
}

// uiMaintainerExists writes a 404 when maintainer {id} does not exist.
func (s *Server) uiMaintainerExists(w http.ResponseWriter, r *http.Request) (uint, bool) {
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return 0, false
	}
	var n int64
	if err := s.DB.Model(&db.Maintainer{}).Where("id = ?", id).Count(&n).Error; err != nil {
		uiInternal(w, err)
		return 0, false
	}
	if n == 0 {
		uiNotFound(w, "maintainer")
		return 0, false
	}
	return id, true
}

// GET /ui/maintainers/{id}/repositories
func (s *Server) uiMaintainerRepositories(w http.ResponseWriter, r *http.Request) {
	p, err := parseListPage(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	id, ok := s.uiMaintainerExists(w, r)
	if !ok {
		return
	}
	s.inventoryRepoPage(w, p, func(q *gorm.DB) *gorm.DB {
		return q.Where("repositories.id IN (?)", s.uiMaintainerRepoIDs(id))
	})
}

// GET /ui/maintainers/{id}/findings: the curated findings across the
// maintainer's repositories, paged and with closed findings excluded (the
// HTML page loads them uncapped and unfiltered, a defect not carried over).
func (s *Server) uiMaintainerFindings(w http.ResponseWriter, r *http.Request) {
	p, err := parseListPage(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	id, ok := s.uiMaintainerExists(w, r)
	if !ok {
		return
	}
	s.inventoryFindingPage(w, p,
		func() *gorm.DB {
			return s.DB.Where("repository_id IN (?)", s.uiMaintainerRepoIDs(id)).
				Where("status NOT IN ?", db.ClosedFindingLifecycles).
				Where("scan_id IN (?)", findingsScanIDs(s.DB))
		},
		func(q *gorm.DB) *gorm.DB { return q.Order("id desc") })
}
