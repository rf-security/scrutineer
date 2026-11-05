package web

import (
	"fmt"
	"net/http"
	"strings"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// Advisories on the /api/v1/ui surface (02-api-plan.md #75, F-ADV-01/02).

// uiAdvisoryRows projects advisories as UIAdvisory rows: the repository ref,
// the newest fix-audit verdict and, when that verdict is fixed, the
// certificate download path (advisoryCertificateDownload).
func (s *Server) uiAdvisoryRows(advisories []db.Advisory) []map[string]any {
	repos := loadRepoMap(s.DB, advisories, advisoryRepoID)
	audits := s.latestAdvisoryAuditStatuses(advisories)
	out := make([]map[string]any, len(advisories))
	for i, a := range advisories {
		status := audits[a.ID]
		cert := ""
		if status == advisoryAuditFixed {
			cert = fmt.Sprintf("/advisories/%d/certificate.json", a.ID)
		}
		out[i] = map[string]any{
			"id":              a.ID,
			"uuid":            a.UUID,
			uiKeyTitle:        a.Title,
			"description":     a.Description,
			"severity":        a.Severity,
			"cvss_score":      a.CVSSScore,
			uiKeyPackages:     a.Packages,
			"published_at":    a.PublishedAt,
			"withdrawn_at":    a.WithdrawnAt,
			"url":             a.URL,
			"classification":  a.Classification,
			"repository":      uiRepoRefMap(repos[a.RepositoryID]),
			"subproject_id":   a.SubprojectID,
			"audit_status":    status,
			"certificate_url": cert,
			uiKeyCreatedAt:    a.CreatedAt,
		}
	}
	return out
}

// uiAdvisoryListParams are the parsed filters of GET /ui/advisories.
type uiAdvisoryListParams struct {
	page         listPage
	severity     string
	search       string
	repositoryID uint
	sort         string
}

func parseUIAdvisoryListParams(r *http.Request) (uiAdvisoryListParams, error) {
	var p uiAdvisoryListParams
	var err error
	if p.page, err = parseListPage(r); err != nil {
		return p, err
	}
	if p.repositoryID, err = uiQueryID(r, repositoryIDKey); err != nil {
		return p, err
	}
	q := r.URL.Query()
	// Advisory severities are free-form upstream values; the `severities`
	// facet lists the ones present, and an unknown value simply matches none.
	p.severity = q.Get("severity")
	p.search = strings.TrimSpace(q.Get("q"))
	p.sort = q.Get("sort")
	return p, nil
}

// where applies the advisories index's filters.
func (p uiAdvisoryListParams) where(q *gorm.DB) *gorm.DB {
	if p.severity != "" {
		q = q.Where("advisories.severity = ?", p.severity)
	}
	if p.repositoryID != 0 {
		q = q.Where("advisories.repository_id = ?", p.repositoryID)
	}
	if p.search != "" {
		like := "%" + p.search + "%"
		q = q.Where("LOWER(advisories.title) LIKE LOWER(?) OR LOWER(advisories.packages) LIKE LOWER(?) OR "+
			"LOWER(advisories.classification) LIKE LOWER(?) OR LOWER(advisories.uuid) LIKE LOWER(?)",
			like, like, like, like)
	}
	return q
}

// uiAdvisoriesOrder mirrors the sort switch of the HTML advisories page so
// URL sort tokens are portable. TODO(WP-API-5): share one extracted
// advisoriesOrderBy with server.go:advisoriesList once server.go extraction
// is coordinated (left untouched here to keep server.go conflict-free).
func uiAdvisoriesOrder(q *gorm.DB, token string) *gorm.DB {
	sortCol, dir := splitSort(token)
	switch sortCol {
	case defaultSort:
		return q.Order(orderByExpr("advisories.published_at", dir, true)).Order("advisories.id desc")
	case sortRepository:
		return q.Joins("JOIN repositories r ON r.id = advisories.repository_id").
			Order(orderByExpr("r.name", dir, false)).
			Order("advisories.cvss_score desc")
	case uiKeyTitle:
		return q.Order(orderByExpr("advisories.title", dir, false)).Order("advisories.id desc")
	case sortSeverity:
		return q.Order(orderByExpr("advisories.cvss_score", dir, true)).Order("advisories.id desc")
	default:
		return q.Order("advisories.cvss_score desc, advisories.id desc")
	}
}

// GET /ui/advisories
func (s *Server) uiAdvisoryList(w http.ResponseWriter, r *http.Request) {
	p, err := parseUIAdvisoryListParams(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	var total int64
	if err := p.where(s.DB.Model(&db.Advisory{})).Count(&total).Error; err != nil {
		uiInternal(w, err)
		return
	}
	var rows []db.Advisory
	q := uiAdvisoriesOrder(p.where(s.DB.Model(&db.Advisory{})), p.sort).Select("advisories.*").
		Limit(p.page.PageSize).Offset(p.page.offset())
	if err := q.Find(&rows).Error; err != nil {
		uiInternal(w, err)
		return
	}
	var severities []string
	s.DB.Model(&db.Advisory{}).Where("severity != ''").Distinct("severity").
		Order("severity").Pluck("severity", &severities)
	writeListWith(w, s.uiAdvisoryRows(rows), total, p.page, map[string]any{"severities": nonNilStrings(severities)})
}
