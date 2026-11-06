package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// Packages on the /api/v1/ui surface (02-api-plan.md #73-#74,
// F-PKG-01/02).

// uiPackageListParams are the parsed filters of GET /ui/packages.
type uiPackageListParams struct {
	page      listPage
	ecosystem string
	search    string
	sort      string
}

// where applies the packages index's ecosystem and free-text filters.
func (p uiPackageListParams) where(q *gorm.DB) *gorm.DB {
	if p.ecosystem != "" {
		q = q.Where("ecosystem = ?", p.ecosystem)
	}
	if p.search != "" {
		like := "%" + p.search + "%"
		// GORM maps the PURL struct field to the `p_url` column.
		q = q.Where("LOWER(name) LIKE LOWER(?) OR LOWER(p_url) LIKE LOWER(?) OR LOWER(licenses) LIKE LOWER(?)", like, like, like)
	}
	return q
}

// uiPackagesOrder mirrors the sort switch of the HTML packages page so URL
// sort tokens are portable. TODO(WP-API-5): share one extracted
// packagesOrderBy with server.go:packages once server.go extraction is
// coordinated (left untouched here to keep server.go conflict-free).
func uiPackagesOrder(q *gorm.DB, token string) *gorm.DB {
	sortCol, dir := splitSort(token)
	switch sortCol {
	case uiKeyName:
		return q.Order(orderByExpr(uiKeyName, dir, false))
	case "downloads":
		return q.Order(orderByExpr("downloads", dir, true))
	case "dependents":
		return q.Order(orderByExpr("dependent_repos", dir, true))
	case uiKeyEcosystem:
		return q.Order(orderByExpr(uiKeyEcosystem, dir, false)).Order(uiKeyName)
	case "registry":
		return q.Order(orderByExpr("registry_url", dir, false)).Order(uiKeyName)
	case "latest":
		return q.Order(orderByExpr("latest_release_at", dir, true)).Order(uiKeyName)
	default:
		return q.Order(uiKeyName)
	}
}

// registryDomain is the host of a registry URL (the template `domain` func).
func registryDomain(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	if i := strings.IndexByte(u, '/'); i >= 0 {
		u = u[:i]
	}
	return u
}

// uiPackageRow is the UIPackage projection. p.Repository is used for the
// repository ref when loaded.
func uiPackageRow(p db.Package) map[string]any {
	flags := db.PackageRiskFlags(p.RiskFlags)
	if flags == nil {
		flags = []string{}
	}
	return map[string]any{
		"id":                     p.ID,
		uiKeyName:                p.Name,
		uiKeyEcosystem:           p.Ecosystem,
		"registry":               registryDomain(p.RegistryURL),
		"registry_url":           p.RegistryURL,
		"latest_version":         p.LatestVersion,
		"versions_count":         p.VersionsCount,
		"licenses":               p.Licenses,
		"latest_release_at":      p.LatestReleaseAt,
		"downloads":              p.Downloads,
		"dependents":             p.DependentRepos,
		"dependent_packages":     p.DependentPackages,
		"dependent_repos":        p.DependentRepos,
		"dependent_packages_url": p.DependentPackagesURL,
		uiKeyRepository:          uiRepoRefMap(p.Repository),
		"subproject_id":          p.SubprojectID,
		uiKeyPURL:                p.PURL,
		"risk_flags":             flags,
		uiKeyCreatedAt:           p.CreatedAt,
	}
}

// uiPackageColumns are the columns a package row reads (metadata is only
// loaded by the detail).
var uiPackageColumns = []string{"id", repositoryIDKey, "subproject_id", uiKeyName, uiKeyEcosystem, "p_url", "licenses",
	"latest_version", "versions_count", "downloads", "dependent_packages", "dependent_repos", "registry_url",
	"latest_release_at", "dependent_packages_url", "risk_flags", uiKeyCreatedAt}

// GET /ui/packages
func (s *Server) uiPackageList(w http.ResponseWriter, r *http.Request) {
	page, err := parseListPage(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	p := uiPackageListParams{page: page, ecosystem: r.URL.Query().Get(uiKeyEcosystem),
		search: strings.TrimSpace(r.URL.Query().Get("q")), sort: r.URL.Query().Get("sort")}
	var total int64
	if err := p.where(s.DB.Model(&db.Package{})).Count(&total).Error; err != nil {
		uiInternal(w, err)
		return
	}
	var rows []db.Package
	q := uiPackagesOrder(p.where(s.DB.Model(&db.Package{})), p.sort).Select(uiPackageColumns).
		Preload("Repository", func(tx *gorm.DB) *gorm.DB { return tx.Select("id", uiKeyName) }).
		Limit(p.page.PageSize).Offset(p.page.offset())
	if err := q.Find(&rows).Error; err != nil {
		uiInternal(w, err)
		return
	}
	items := make([]map[string]any, len(rows))
	for i, row := range rows {
		items[i] = uiPackageRow(row)
	}
	var ecosystems []string
	s.DB.Model(&db.Package{}).Distinct(uiKeyEcosystem).Order(uiKeyEcosystem).Pluck(uiKeyEcosystem, &ecosystems)
	writeListWith(w, items, total, p.page, map[string]any{"ecosystems": nonNilStrings(ecosystems)})
}

// GET /ui/packages/{id}
func (s *Server) uiPackageShow(w http.ResponseWriter, r *http.Request) {
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return
	}
	var p db.Package
	if err := s.DB.Preload("Repository", func(tx *gorm.DB) *gorm.DB { return tx.Select("id", uiKeyName) }).
		First(&p, id).Error; err != nil {
		uiDBError(w, err, "package")
		return
	}
	flags := []map[string]string{}
	for _, f := range db.PackageRiskFlags(p.RiskFlags) {
		flags = append(flags, map[string]string{"id": f, "label": db.PackageRiskFlagLabel(f)})
	}
	writeUIJSON(w, http.StatusOK, map[string]any{
		"package":       uiPackageRow(p),
		uiKeyRepository: uiRepoRefMap(p.Repository),
		"risk_flags":    flags,
		"metadata":      uiPackageMetadata(p.Metadata),
	})
}

// uiPackageMetadata is the stored ecosyste.ms metadata as raw JSON; nil when
// empty or not valid JSON.
func uiPackageMetadata(raw string) json.RawMessage {
	if strings.TrimSpace(raw) == "" || !json.Valid([]byte(raw)) {
		return nil
	}
	return json.RawMessage(raw)
}
