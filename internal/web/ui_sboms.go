package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/git-pkgs/sbom"
	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// SBOMs on the /api/v1/ui surface (02-api-plan.md #76-#81, F-SBOM-01..06).

const (
	sbomStateResolving = "resolving"
	sbomStateResolved  = "resolved"
	sbomStateError     = "error"

	sbomResolutionLinked         = "linked"
	sbomResolutionAwaitingImport = "awaiting_import"

	uiKeyScope = "scope"
)

// sbomUploadSummaryOmit keeps the stored document out of every UI read.
var sbomUploadSummaryOmit = []string{"raw"}

// uiSBOMRow is the SBOM projection. resolving is true while a confirmed
// upload still has packages with neither a repository nor an error.
func uiSBOMRow(up db.SBOMUpload, resolving bool) map[string]any {
	return map[string]any{
		"id":             up.ID,
		uiKeyName:        up.Name,
		"filename":       up.Filename,
		"format":         up.Format,
		"spec_version":   up.SpecVersion,
		"origin":         up.Origin,
		"package_count":  up.PackageCount,
		"import_pending": up.ImportPending,
		"resolving":      resolving,
		uiKeyCreatedAt:   up.CreatedAt,
		"updated_at":     up.UpdatedAt,
	}
}

// sbomResolvingIDs returns which of the uploads still have unresolved
// packages (no repository and no error yet).
func (s *Server) sbomResolvingIDs(ups []db.SBOMUpload) map[uint]bool {
	ids := make([]uint, 0, len(ups))
	for _, up := range ups {
		if !up.ImportPending {
			ids = append(ids, up.ID)
		}
	}
	out := map[uint]bool{}
	if len(ids) == 0 {
		return out
	}
	var pending []uint
	s.DB.Model(&db.SBOMPackage{}).Distinct("sbom_upload_id").
		Where("sbom_upload_id IN ? AND source_repository_id IS NULL AND resolve_error = ''", ids).
		Pluck("sbom_upload_id", &pending)
	for _, id := range pending {
		out[id] = true
	}
	return out
}

func (s *Server) uiSBOMRows(ups []db.SBOMUpload) []map[string]any {
	resolving := s.sbomResolvingIDs(ups)
	out := make([]map[string]any, len(ups))
	for i, up := range ups {
		out[i] = uiSBOMRow(up, resolving[up.ID])
	}
	return out
}

// loadUISBOM resolves {id} to an upload (without its document), writing a
// 400/404 on failure.
func (s *Server) loadUISBOM(w http.ResponseWriter, r *http.Request) (db.SBOMUpload, bool) {
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return db.SBOMUpload{}, false
	}
	var up db.SBOMUpload
	if err := s.DB.Omit(sbomUploadSummaryOmit...).First(&up, id).Error; err != nil {
		uiDBError(w, err, "sbom")
		return db.SBOMUpload{}, false
	}
	return up, true
}

func (s *Server) uiSBOMRowFor(up db.SBOMUpload) map[string]any {
	return uiSBOMRow(up, s.sbomResolvingIDs([]db.SBOMUpload{up})[up.ID])
}

// sbomProgress counts an upload's packages and how many are resolved (linked
// to a repository or carrying a resolve error).
type sbomProgress struct {
	Total      int
	Resolved   int
	Linked     int
	Direct     int
	Transitive int
}

func (s *Server) sbomProgressCounts(id uint) (sbomProgress, error) {
	var c sbomProgress
	err := s.DB.Model(&db.SBOMPackage{}).Select(`COUNT(*) AS total,
		COALESCE(SUM(CASE WHEN source_repository_id IS NOT NULL OR resolve_error != '' THEN 1 ELSE 0 END), 0) AS resolved,
		COALESCE(SUM(CASE WHEN source_repository_id IS NOT NULL THEN 1 ELSE 0 END), 0) AS linked,
		COALESCE(SUM(CASE WHEN scope = ? THEN 1 ELSE 0 END), 0) AS direct,
		COALESCE(SUM(CASE WHEN scope = ? THEN 1 ELSE 0 END), 0) AS transitive`, sbom.ScopeDirect, sbom.ScopeTransitive).
		Where("sbom_upload_id = ?", id).Scan(&c).Error
	return c, err
}

// publishSBOMProgress publishes the `sbom` event: "resolving" when a run
// starts; when it finishes, "resolved" if every package is linked or carries
// a resolve error, "error" if the run left packages unresolved (it aborted
// or timed out).
func (s *Server) publishSBOMProgress(id uint, finished bool) {
	c, err := s.sbomProgressCounts(id)
	if err != nil {
		s.Log.Warn("sbom progress counts", "sbom", id, "err", err)
		return
	}
	state := sbomStateResolving
	if finished {
		state = sbomStateResolved
		if c.Resolved < c.Total {
			state = sbomStateError
		}
	}
	s.publishSBOM(id, state, c.Resolved, c.Total)
}

// GET /ui/sboms
func (s *Server) uiSBOMList(w http.ResponseWriter, r *http.Request) {
	p, err := parseListPage(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	// Uploads only, as sbomList: generated per-repository snapshots surface
	// via the repository views.
	base := func() *gorm.DB {
		return s.DB.Model(&db.SBOMUpload{}).Where("origin = ?", db.SBOMOriginUploaded)
	}
	var total int64
	if err := base().Count(&total).Error; err != nil {
		uiInternal(w, err)
		return
	}
	q, _ := sbomListOrder(base(), r.URL.Query().Get("sort"))
	var rows []db.SBOMUpload
	if err := q.Omit(sbomUploadSummaryOmit...).Limit(p.PageSize).Offset(p.offset()).Find(&rows).Error; err != nil {
		uiInternal(w, err)
		return
	}
	writeList(w, s.uiSBOMRows(rows), total, p)
}

// POST /ui/sboms (multipart `file`)
func (s *Server) uiSBOMUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, sbomMaxUploadBytes)
	file, header, err := r.FormFile("file")
	if err != nil {
		uiBadParam(w, "file required: "+err.Error())
		return
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(file)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	up, err := s.createSBOMUpload(data, header.Filename)
	if err != nil {
		var perr sbomParseError
		if errors.As(err, &perr) {
			writeUIFields(w, uiFieldErrors{"file": err.Error()})
			return
		}
		uiInternal(w, err)
		return
	}
	writeUIJSON(w, http.StatusCreated, uiSBOMRow(up, false))
}

// uiSBOMScope reads the optional `scope` filter.
func uiSBOMScope(r *http.Request) (string, error) {
	scope := r.URL.Query().Get(uiKeyScope)
	if scope != "" && scope != sbom.ScopeDirect && scope != sbom.ScopeTransitive {
		return "", fmt.Errorf("scope must be %q or %q, got %q", sbom.ScopeDirect, sbom.ScopeTransitive, scope)
	}
	return scope, nil
}

// sbomRepoIDs returns the existing repositories an upload's packages resolved
// to, optionally limited to one scope.
func (s *Server) sbomRepoIDs(id uint, scope string) ([]uint, error) {
	q := s.DB.Model(&db.SBOMPackage{}).Distinct("sbom_packages.source_repository_id").
		Joins("JOIN repositories ON repositories.id = sbom_packages.source_repository_id").
		Where("sbom_packages.sbom_upload_id = ?", id)
	if scope != "" {
		q = q.Where("sbom_packages.scope = ?", scope)
	}
	var ids []uint
	err := q.Pluck("sbom_packages.source_repository_id", &ids).Error
	return ids, err
}

// GET /ui/sboms/{id}
func (s *Server) uiSBOMShow(w http.ResponseWriter, r *http.Request) {
	up, ok := s.loadUISBOM(w, r)
	if !ok {
		return
	}
	c, err := s.sbomProgressCounts(up.ID)
	if err != nil {
		uiInternal(w, err)
		return
	}
	repoIDs, err := s.sbomRepoIDs(up.ID, "")
	if err != nil {
		uiInternal(w, err)
		return
	}
	var findings, advisories int64
	if len(repoIDs) > 0 {
		s.sbomFindingsQuery(repoIDs, "", "").Model(&db.Finding{}).Count(&findings)
		s.sbomAdvisoriesQuery(repoIDs).Model(&db.Advisory{}).Count(&advisories)
	}
	row := s.uiSBOMRowFor(up)
	row["counts"] = map[string]any{
		"packages": c.Total, "resolved": c.Resolved, "linked": c.Linked,
		"direct": c.Direct, "transitive": c.Transitive,
		uiKeyFindings: findings, "advisories": advisories,
	}
	row["has_scope"] = c.Direct+c.Transitive > 0
	writeUIJSON(w, http.StatusOK, row)
}

// uiSBOMPackageRow is the SBOMPackage projection with its resolution state.
func uiSBOMPackageRow(p db.SBOMPackage, importPending bool) map[string]any {
	res := map[string]any{"repository": nil}
	switch {
	case p.SourceRepository != nil:
		res["state"] = sbomResolutionLinked
		res["repository"] = uiRepoRef(*p.SourceRepository)
	case p.ResolveError != "":
		res["state"] = sbomStateError
		res[errorKey] = p.ResolveError
	case importPending:
		res["state"] = sbomResolutionAwaitingImport
	default:
		res["state"] = sbomStateResolving
	}
	return map[string]any{
		"id":         p.ID,
		uiKeyName:    p.Name,
		"version":    p.Version,
		"ecosystem":  p.Ecosystem,
		"purl":       p.PURL,
		"license":    p.License,
		uiKeyScope:   p.Scope,
		"resolution": res,
	}
}

// GET /ui/sboms/{id}/packages
func (s *Server) uiSBOMPackages(w http.ResponseWriter, r *http.Request) {
	p, err := parseListPage(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	scope, err := uiSBOMScope(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	up, ok := s.loadUISBOM(w, r)
	if !ok {
		return
	}
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	base := func() *gorm.DB {
		q := s.DB.Model(&db.SBOMPackage{}).Where("sbom_upload_id = ?", up.ID)
		if scope != "" {
			q = q.Where("scope = ?", scope)
		}
		if search != "" {
			like := "%" + search + "%"
			q = q.Where("LOWER(name) LIKE LOWER(?) OR LOWER(p_url) LIKE LOWER(?)", like, like)
		}
		return q
	}
	var total int64
	if err := base().Count(&total).Error; err != nil {
		uiInternal(w, err)
		return
	}
	var pkgs []db.SBOMPackage
	if err := base().Preload("SourceRepository", func(tx *gorm.DB) *gorm.DB { return tx.Select("id", uiKeyName) }).
		Order("id").Limit(p.PageSize).Offset(p.offset()).Find(&pkgs).Error; err != nil {
		uiInternal(w, err)
		return
	}
	items := make([]map[string]any, len(pkgs))
	for i, pkg := range pkgs {
		items[i] = uiSBOMPackageRow(pkg, up.ImportPending)
	}
	writeList(w, items, total, p)
}

// GET /ui/sboms/{id}/findings
func (s *Server) uiSBOMFindings(w http.ResponseWriter, r *http.Request) {
	p, err := parseListPage(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	scope, err := uiSBOMScope(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	q := r.URL.Query()
	severity, category := q.Get("severity"), q.Get("category")
	if severity != "" && !slices.Contains(db.SeverityLevels, severity) {
		uiBadParam(w, fmt.Sprintf("unknown severity %q", severity))
		return
	}
	if !validCWECategory(category) {
		uiBadParam(w, fmt.Sprintf("unknown category %q", category))
		return
	}
	up, ok := s.loadUISBOM(w, r)
	if !ok {
		return
	}
	repoIDs, err := s.sbomRepoIDs(up.ID, scope)
	if err != nil {
		uiInternal(w, err)
		return
	}
	if len(repoIDs) == 0 {
		writeList(w, []map[string]any{}, 0, p)
		return
	}
	sortCol, dir := splitSort(q.Get("sort"))
	s.inventoryFindingPage(w, p,
		func() *gorm.DB { return s.sbomFindingsQuery(repoIDs, severity, category) },
		func(q *gorm.DB) *gorm.DB {
			q, _, _ = sbomFindingsOrder(q, sortCol, dir)
			return q
		})
}

// GET /ui/sboms/{id}/advisories
func (s *Server) uiSBOMAdvisories(w http.ResponseWriter, r *http.Request) {
	p, err := parseListPage(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	scope, err := uiSBOMScope(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	up, ok := s.loadUISBOM(w, r)
	if !ok {
		return
	}
	repoIDs, err := s.sbomRepoIDs(up.ID, scope)
	if err != nil {
		uiInternal(w, err)
		return
	}
	if len(repoIDs) == 0 {
		writeList(w, []map[string]any{}, 0, p)
		return
	}
	s.inventoryAdvisoryPage(w, p, func() *gorm.DB { return s.sbomAdvisoriesQuery(repoIDs) },
		"cvss_score desc, published_at desc, id desc", nil)
}

// POST /ui/sboms/{id}/actions/confirm: sbomConfirm's JSON twin. May enqueue
// triage scans for the direct dependencies the resolver links.
func (s *Server) uiSBOMConfirm(w http.ResponseWriter, r *http.Request) {
	up, ok := s.loadUISBOM(w, r)
	if !ok {
		return
	}
	if !up.ImportPending {
		writeUIError(w, http.StatusConflict, uiCodeConflict, "SBOM import already confirmed", nil)
		return
	}
	started, err := s.confirmSBOMImport(up.ID)
	if err != nil {
		uiInternal(w, err)
		return
	}
	if !started {
		writeUIError(w, http.StatusConflict, uiCodeConflict, "SBOM import already confirmed", nil)
		return
	}
	writeUIJSON(w, http.StatusAccepted, map[string]any{"importing": up.PackageCount})
}

// POST /ui/sboms/{id}/actions/resolve: sbomResolve's JSON twin (background
// re-resolution; links repositories, triages direct dependencies of uploads).
func (s *Server) uiSBOMResolve(w http.ResponseWriter, r *http.Request) {
	up, ok := s.loadUISBOM(w, r)
	if !ok {
		return
	}
	if up.ImportPending {
		writeUIError(w, http.StatusConflict, uiCodeConflict, "confirm SBOM import before resolving repositories", nil)
		return
	}
	s.goResolve(up.ID)
	writeUIJSON(w, http.StatusAccepted, s.uiSBOMRowFor(up))
}

// DELETE /ui/sboms/{id}
func (s *Server) uiSBOMDelete(w http.ResponseWriter, r *http.Request) {
	up, ok := s.loadUISBOM(w, r)
	if !ok {
		return
	}
	if err := s.deleteSBOM(int(up.ID)); err != nil {
		uiInternal(w, err)
		return
	}
	w.Header().Set(cacheControlHeader, noStore)
	w.WriteHeader(http.StatusNoContent)
}
