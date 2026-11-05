package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// Orgs on the /api/v1/ui surface (02-api-plan.md #67-#69, F-ORG-01..03).

// uiOrgOpenFindingsSort is the JSON-only sort token for the open-findings
// count (the badge the SPA shows); "findings" keeps the HTML page's meaning.
const uiOrgOpenFindingsSort = "open_findings"

// GET /ui/orgs
func (s *Server) uiOrgList(w http.ResponseWriter, r *http.Request) {
	p, err := parseListPage(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	rows := s.orgRows(strings.TrimSpace(r.URL.Query().Get("q")))
	open := s.orgOpenFindingCounts()
	token := r.URL.Query().Get("sort")
	if col, dir := splitSort(token); col == uiOrgOpenFindingsSort {
		sortSlice(rows, dirLess(dir, "desc", func(a, b orgRow) bool { return open[a.Owner] < open[b.Owner] }))
	} else {
		sortOrgRows(rows, token)
	}
	total := len(rows)
	start := min(p.offset(), total)
	end := min(start+p.PageSize, total)
	items := make([]map[string]any, 0, end-start)
	for _, row := range rows[start:end] {
		items = append(items, map[string]any{
			"owner": row.Owner,
			"repos": row.Repos,
			// findings_total is the HTML page's number, which counts closed
			// findings too; open_findings excludes them (what the badge shows).
			"findings_total": row.FindingsTotal,
			"open_findings":  open[row.Owner],
			"last_activity":  row.LastActivity,
		})
	}
	writeList(w, items, int64(total), p)
}

// orgOpenFindingCounts counts each owner's open, curated findings: the
// orgRows total with the closed lifecycles excluded, as every other count.
func (s *Server) orgOpenFindingCounts() map[string]int {
	var counts []struct {
		Owner string
		N     int
	}
	s.DB.Raw(`
		SELECT r.owner, COUNT(f.id) AS n
		FROM repositories r
		JOIN findings f ON f.repository_id = r.id
		LEFT JOIN scans s ON s.id = f.scan_id
		WHERE r.owner != ''
		  AND f.status NOT IN (` + db.ClosedFindingLifecycleSQLValues() + `)
		  AND ` + aliasedFindingsScanFilter + `
		GROUP BY r.owner
	`).Scan(&counts)
	out := make(map[string]int, len(counts))
	for _, c := range counts {
		out[c.Owner] = c.N
	}
	return out
}

// uiOrgRepoIDs resolves {login} to its repository ids, writing a 404 when the
// owner has none.
func (s *Server) uiOrgRepoIDs(w http.ResponseWriter, r *http.Request) (string, []uint, bool) {
	owner := r.PathValue("login")
	var ids []uint
	if owner != "" {
		if err := s.DB.Model(&db.Repository{}).Where("owner = ?", owner).Pluck("id", &ids).Error; err != nil {
			uiInternal(w, err)
			return "", nil, false
		}
	}
	if len(ids) == 0 {
		uiNotFound(w, "org")
		return "", nil, false
	}
	return owner, ids, true
}

// orgMaintainerIDs selects the distinct maintainers of an org's repositories.
func (s *Server) orgMaintainerIDs(repoIDs []uint) *gorm.DB {
	return s.DB.Table("repository_maintainers").Select("DISTINCT maintainer_id").Where("repository_id IN ?", repoIDs)
}

// GET /ui/orgs/{login}
func (s *Server) uiOrgShow(w http.ResponseWriter, r *http.Request) {
	owner, repoIDs, ok := s.uiOrgRepoIDs(w, r)
	if !ok {
		return
	}
	var findings, advisories, maintainers int64
	if err := s.orgFindingsQuery(repoIDs, "").Model(&db.Finding{}).Count(&findings).Error; err != nil {
		uiInternal(w, err)
		return
	}
	s.DB.Model(&db.Advisory{}).Where("repository_id IN ?", repoIDs).Count(&advisories)
	s.DB.Model(&db.Maintainer{}).Where("id IN (?)", s.orgMaintainerIDs(repoIDs)).Count(&maintainers)

	date := time.Now().UTC().Format("20060102")
	base := "/orgs/" + url.PathEscape(owner)
	writeUIJSON(w, http.StatusOK, map[string]any{
		"owner":      owner,
		"repo_count": len(repoIDs),
		"counts":     map[string]any{uiKeyFindings: findings, "advisories": advisories, "maintainers": maintainers},
		"exports": map[string]any{
			"summary_md": map[string]any{
				"url":      base + "/summary.md",
				"filename": fmt.Sprintf("scrutineer-%s-summary-%s.md", sanitiseFilename(owner), date),
			},
			"findings_md": map[string]any{
				"url":      base + "/findings.md",
				"filename": fmt.Sprintf("scrutineer-%s-findings-%s.md", sanitiseFilename(owner), date),
			},
		},
	})
}

// GET /ui/orgs/{login}/repositories
func (s *Server) uiOrgRepositories(w http.ResponseWriter, r *http.Request) {
	p, err := parseListPage(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	owner, _, ok := s.uiOrgRepoIDs(w, r)
	if !ok {
		return
	}
	s.inventoryRepoPage(w, p, func(q *gorm.DB) *gorm.DB { return q.Where("repositories.owner = ?", owner) })
}

// GET /ui/orgs/{login}/findings
func (s *Server) uiOrgFindings(w http.ResponseWriter, r *http.Request) {
	p, err := parseListPage(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	category := r.URL.Query().Get("category")
	if !validCWECategory(category) {
		uiBadParam(w, fmt.Sprintf("unknown category %q", category))
		return
	}
	_, repoIDs, ok := s.uiOrgRepoIDs(w, r)
	if !ok {
		return
	}
	// Severity (Critical first), then newest within a severity: orgShow's order.
	s.inventoryFindingPage(w, p,
		func() *gorm.DB { return s.orgFindingsQuery(repoIDs, category) },
		func(q *gorm.DB) *gorm.DB { return q.Order(severityOrder).Order("id desc") })
}

// GET /ui/orgs/{login}/advisories
func (s *Server) uiOrgAdvisories(w http.ResponseWriter, r *http.Request) {
	p, err := parseListPage(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	_, repoIDs, ok := s.uiOrgRepoIDs(w, r)
	if !ok {
		return
	}
	s.inventoryAdvisoryPage(w, p,
		func() *gorm.DB { return s.DB.Where("repository_id IN ?", repoIDs) },
		"cvss_score desc, id desc", nil)
}

// GET /ui/orgs/{login}/maintainers
func (s *Server) uiOrgMaintainers(w http.ResponseWriter, r *http.Request) {
	p, err := parseListPage(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	_, repoIDs, ok := s.uiOrgRepoIDs(w, r)
	if !ok {
		return
	}
	q := func() *gorm.DB {
		return s.DB.Model(&db.Maintainer{}).Where("maintainers.id IN (?)", s.orgMaintainerIDs(repoIDs))
	}
	s.maintainerPage(w, p, q, func(q *gorm.DB) *gorm.DB { return q.Order("maintainers.name").Order("maintainers.id") })
}
