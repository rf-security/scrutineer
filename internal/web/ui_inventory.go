package web

import (
	"net/http"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// registerUIInventoryRoutes registers the orgs, maintainers, packages, advisories and SBOM routes of the /api/v1/ui surface
// (02-api-plan.md section 3.6 #67-#81). Owned by WP-API-5: handlers live in
// ui_orgs.go, ui_maintainers.go, ui_packages.go, ui_advisories.go and
// ui_sboms.go; each route is documented in openapi.yaml between the
// "# --- ui:inventory begin/end ---" markers.
// TestOpenAPICoversRegisteredAPIRoutes fails on any undocumented route.
func (s *Server) registerUIInventoryRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /ui/orgs", s.uiOrgList)
	mux.HandleFunc("GET /ui/orgs/{login}", s.uiOrgShow)
	mux.HandleFunc("GET /ui/orgs/{login}/repositories", s.uiOrgRepositories)
	mux.HandleFunc("GET /ui/orgs/{login}/findings", s.uiOrgFindings)
	mux.HandleFunc("GET /ui/orgs/{login}/advisories", s.uiOrgAdvisories)
	mux.HandleFunc("GET /ui/orgs/{login}/maintainers", s.uiOrgMaintainers)

	mux.HandleFunc("GET /ui/maintainers", s.uiMaintainerList)
	mux.HandleFunc("GET /ui/maintainers/{id}", s.uiMaintainerShow)
	mux.HandleFunc("PATCH /ui/maintainers/{id}", s.uiMaintainerPatch)
	mux.HandleFunc("GET /ui/maintainers/{id}/repositories", s.uiMaintainerRepositories)
	mux.HandleFunc("GET /ui/maintainers/{id}/findings", s.uiMaintainerFindings)

	mux.HandleFunc("GET /ui/packages", s.uiPackageList)
	mux.HandleFunc("GET /ui/packages/{id}", s.uiPackageShow)

	mux.HandleFunc("GET /ui/advisories", s.uiAdvisoryList)

	mux.HandleFunc("GET /ui/sboms", s.uiSBOMList)
	mux.HandleFunc("POST /ui/sboms", s.uiSBOMUpload)
	mux.HandleFunc("GET /ui/sboms/{id}", s.uiSBOMShow)
	mux.HandleFunc("DELETE /ui/sboms/{id}", s.uiSBOMDelete)
	mux.HandleFunc("GET /ui/sboms/{id}/packages", s.uiSBOMPackages)
	mux.HandleFunc("GET /ui/sboms/{id}/findings", s.uiSBOMFindings)
	mux.HandleFunc("GET /ui/sboms/{id}/advisories", s.uiSBOMAdvisories)
	mux.HandleFunc("POST /ui/sboms/{id}/actions/confirm", s.uiSBOMConfirm)
	mux.HandleFunc("POST /ui/sboms/{id}/actions/resolve", s.uiSBOMResolve)
}

// ---------------------------------------------------------------- shared inventory helpers

// uiRepoRef is the RepoRef object ({id,name}); nil when the repository is
// unknown.
func uiRepoRef(repo db.Repository) map[string]any {
	if repo.ID == 0 {
		return nil
	}
	return map[string]any{"id": repo.ID, uiKeyName: repo.Name}
}

// inventoryRepoPage writes a RepoRow page of the repositories matching where
// (applied to the repositories table), ordered by name.
func (s *Server) inventoryRepoPage(w http.ResponseWriter, p listPage, where func(*gorm.DB) *gorm.DB) {
	var total int64
	if err := where(s.DB.Model(&db.Repository{})).Count(&total).Error; err != nil {
		uiInternal(w, err)
		return
	}
	var rows []repositoryExportRow
	q := where(s.repositoryExportQuery()).Order("repositories.name").Order("repositories.id").
		Limit(p.PageSize).Offset(p.offset())
	if err := q.Scan(&rows).Error; err != nil {
		uiInternal(w, err)
		return
	}
	ids := make([]uint, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	repos := map[uint]db.Repository{}
	if len(ids) > 0 {
		var full []db.Repository
		if err := s.DB.Select(uiRepoRowColumns).Where("id IN ?", ids).Find(&full).Error; err != nil {
			uiInternal(w, err)
			return
		}
		for _, r := range full {
			repos[r.ID] = r
		}
	}
	items := make([]map[string]any, len(rows))
	for i, row := range rows {
		items[i] = uiRepoRow(row, repos[row.ID])
	}
	writeList(w, items, total, p)
}

// uiRepoRowColumns are the repository columns uiRepoRow reads beyond the
// export row (the blob/cache columns are never loaded).
var uiRepoRowColumns = []string{"id", "clone_error", "default_branch", "archived", "pushed_at", "description",
	"license", "forks", "federation_opt_out_at"}

// inventoryFindingPage writes a FindingRow page of q (a findings query with
// filters applied); order is applied after the count.
func (s *Server) inventoryFindingPage(w http.ResponseWriter, p listPage, q func() *gorm.DB, order func(*gorm.DB) *gorm.DB) {
	var total int64
	if err := q().Model(&db.Finding{}).Count(&total).Error; err != nil {
		uiInternal(w, err)
		return
	}
	var findings []db.Finding
	if err := order(q()).Limit(p.PageSize).Offset(p.offset()).Find(&findings).Error; err != nil {
		uiInternal(w, err)
		return
	}
	writeList(w, s.uiFindingRows(findings), total, p)
}

// inventoryAdvisoryPage writes an advisory page of q (an advisories query
// with filters applied); order is applied after the count.
func (s *Server) inventoryAdvisoryPage(w http.ResponseWriter, p listPage, q func() *gorm.DB, order string, extra map[string]any) {
	var total int64
	if err := q().Model(&db.Advisory{}).Count(&total).Error; err != nil {
		uiInternal(w, err)
		return
	}
	var advisories []db.Advisory
	if err := q().Order(order).Limit(p.PageSize).Offset(p.offset()).Find(&advisories).Error; err != nil {
		uiInternal(w, err)
		return
	}
	writeListWith(w, s.uiAdvisoryRows(advisories), total, p, extra)
}

// validCWECategory reports whether category is a filter token the findings
// category dropdown offers (a View-1400 category or UncategorizedCWE).
func validCWECategory(category string) bool {
	if category == "" || category == UncategorizedCWE {
		return true
	}
	for _, c := range CWECategories() {
		if c == category {
			return true
		}
	}
	return false
}
