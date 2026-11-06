package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/git-pkgs/sbom"
	"gorm.io/gorm"

	"scrutineer/internal/db"
)

const (
	sbomMaxUploadBytes  = 32 << 20
	sbomResolveTimeout  = 10 * time.Minute
	sbomInsertBatchSize = 50
)

func (s *Server) registerSBOMRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /sboms", s.sbomList)
	mux.HandleFunc("GET /sboms/new", s.sbomNew)
	mux.HandleFunc("POST /sboms", s.sbomUpload)
	mux.HandleFunc("GET /sboms/{id}", s.sbomShow)
	mux.HandleFunc("POST /sboms/{id}/confirm", s.sbomConfirm)
	mux.HandleFunc("POST /sboms/{id}/resolve", s.sbomResolve)
	mux.HandleFunc("POST /sboms/{id}/delete", s.sbomDelete)
}

func (s *Server) sbomList(w http.ResponseWriter, r *http.Request) {
	// Generated per-repository snapshots share this table but are one row per
	// dependencies scan; listing them here would bury the operator's uploads.
	// They surface via the repository and portfolio views instead.
	q := s.DB.Model(&db.SBOMUpload{}).Where("origin = ?", db.SBOMOriginUploaded)
	sortCol, dir := splitSort(r.URL.Query().Get("sort"))
	switch sortCol {
	case "name":
		q = q.Order(orderByExpr("name", dir, false)).Order("id desc")
	case "format":
		q = q.Order(orderByExpr("format", dir, false)).Order("id desc")
	case "packages":
		q = q.Order(orderByExpr("package_count", dir, true)).Order("id desc")
	case "uploaded":
		q = q.Order(orderByExpr("created_at", dir, true)).Order("id desc")
	default:
		sortCol, dir = defaultSort, ""
		q = q.Order("id desc")
	}
	sort := joinSort(sortCol, dir)

	var total int64
	q.Count(&total)
	page := paginate(r, total)
	var rows []db.SBOMUpload
	q.Limit(perPage).Offset((page.N - 1) * perPage).Find(&rows)
	s.render(w, r, "sboms.html", map[string]any{"SBOMs": rows, "Page": page, "Sort": sort})
}

func (s *Server) sbomNew(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "sbom_new.html", map[string]any{pageTitleKey: "Upload SBOM"})
}

func (s *Server) sbomUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, sbomMaxUploadBytes)
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	doc, err := sbom.Parse(data)
	if err != nil {
		http.Error(w, "parse SBOM: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}

	up := db.SBOMUpload{
		Name:          firstNonEmpty(doc.Document.Name, header.Filename),
		Filename:      header.Filename,
		Format:        string(doc.Type),
		SpecVersion:   doc.SpecVersion,
		Raw:           data,
		Origin:        db.SBOMOriginUploaded,
		PackageCount:  len(doc.Packages),
		ImportPending: true,
	}
	scope := doc.ClassifyScope()
	for _, p := range doc.Packages {
		up.Packages = append(up.Packages, db.SBOMPackage{
			Name:      p.Name,
			Version:   p.Version,
			PURL:      p.PURL(),
			Ecosystem: purlType(p.PURL()),
			License:   firstNonEmpty(p.LicenseDeclared, p.LicenseConcluded),
			Scope:     scope[p.ID],
		})
	}
	if err := s.DB.Session(&gorm.Session{CreateBatchSize: sbomInsertBatchSize}).Create(&up).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.redirect(w, r, fmt.Sprintf("/sboms/%d", up.ID))
}

type sbomScopeCounts struct {
	Direct     int
	Transitive int
	Unknown    int
}

func countSBOMScopes(pkgs []db.SBOMPackage) sbomScopeCounts {
	var counts sbomScopeCounts
	for _, p := range pkgs {
		switch p.Scope {
		case sbom.ScopeDirect:
			counts.Direct++
		case sbom.ScopeTransitive:
			counts.Transitive++
		default:
			counts.Unknown++
		}
	}
	return counts
}

// anyPackageHasScope reports whether at least one package carries a
// direct/transitive scope value; flat-list SBOMs leave them all blank, in
// which case the scope filter is hidden.
func anyPackageHasScope(pkgs []db.SBOMPackage) bool {
	for _, p := range pkgs {
		if p.Scope != "" {
			return true
		}
	}
	return false
}

func (s *Server) sbomShow(w http.ResponseWriter, r *http.Request) {
	var up db.SBOMUpload
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.DB.Preload("Packages.SourceRepository").First(&up, id).Error; err != nil {
		http.NotFound(w, r)
		return
	}

	hasScope := anyPackageHasScope(up.Packages)
	scopeCounts := countSBOMScopes(up.Packages)

	scope := r.URL.Query().Get("scope")
	pkgs := up.Packages
	if hasScope && (scope == sbom.ScopeDirect || scope == sbom.ScopeTransitive) {
		filtered := make([]db.SBOMPackage, 0, len(up.Packages))
		for _, p := range up.Packages {
			if p.Scope == scope {
				filtered = append(filtered, p)
			}
		}
		pkgs = filtered
	} else {
		scope = ""
	}

	reposByID := make(map[uint]db.Repository)
	for _, p := range pkgs {
		if p.SourceRepository != nil {
			reposByID[p.SourceRepository.ID] = *p.SourceRepository
		}
	}
	repoIDs := make([]uint, 0, len(reposByID))
	for id := range reposByID {
		repoIDs = append(repoIDs, id)
	}

	sortCol, dir := splitSort(r.URL.Query().Get("sort"))
	var findings []db.Finding
	var findingsTotal int64
	var advisories []db.Advisory
	var advisoriesTotal int64
	if len(repoIDs) > 0 {
		// Deep-dive findings only — the SBOM "Findings" tab is a
		// downstream-impact view, where lint output from per-repo scanners
		// (zizmor, semgrep) would be misleading at this level.
		q := s.DB.Where("repository_id IN ? AND status NOT IN ?", repoIDs, db.ClosedFindingLifecycles).
			Where("scan_id IN (?)", findingsScanIDs(s.DB))
		if sev := r.URL.Query().Get("severity"); sev != "" {
			q = q.Where("severity = ?", sev)
		}
		if category := r.URL.Query().Get("category"); category != "" {
			q = applyCWECategoryFilter(q, category)
		}
		switch sortCol {
		case sortSeverity:
			// severityOrder ranks the most severe LOWEST, so the "desc" logical
			// default is ascending on the expression; !wantDesc flips it.
			q = q.Order(orderBySuffix("("+severityOrder+")", !wantDesc(dir, true))).Order("findings.id desc")
		case sortRepository:
			q = q.Joins("JOIN repositories r ON r.id = findings.repository_id").
				Order(orderByExpr("r.name", dir, false)).Order("findings.id desc")
		default:
			sortCol, dir = defaultSort, ""
			q = q.Order("id desc")
		}
		q.Model(&db.Finding{}).Count(&findingsTotal)
		q.Limit(tabRowCap).Find(&findings)

		advQ := s.DB.Where("repository_id IN ? AND withdrawn_at IS NULL", repoIDs)
		advQ.Model(&db.Advisory{}).Count(&advisoriesTotal)
		advQ.Order("cvss_score desc, published_at desc").Limit(tabRowCap).Find(&advisories)
	}

	resolved, withRepo := 0, 0
	for _, p := range pkgs {
		if p.SourceRepositoryID != nil || p.ResolveError != "" {
			resolved++
		}
		if p.SourceRepositoryID != nil {
			withRepo++
		}
	}

	s.render(w, r, "sbom_show.html", map[string]any{
		"SBOM": up, "Packages": pkgs, pageTitleKey: up.Name,
		"Findings": findings, "FindingsTotal": findingsTotal,
		"Advisories": advisories, "AdvisoriesTotal": advisoriesTotal,
		"Repos":    reposByID,
		"Resolved": resolved, "WithRepo": withRepo,
		"Severity": r.URL.Query().Get("severity"), "Sort": joinSort(sortCol, dir),
		"Category":   r.URL.Query().Get("category"),
		"Categories": CWECategories(), "Uncategorized": UncategorizedCWE,
		"Scope": scope, "HasScope": hasScope, "ScopeCounts": scopeCounts,
	})
}

// sbomConfirm starts repository resolution for a newly parsed SBOM. The
// conditional update makes a repeated click harmless: only the first request
// changes the pending state and launches the background resolver.
func (s *Server) sbomConfirm(w http.ResponseWriter, r *http.Request) {
	up, ok := loadByID[db.SBOMUpload](s, w, r)
	if !ok {
		return
	}
	result := s.DB.Model(&db.SBOMUpload{}).
		Where("id = ? AND import_pending = ?", up.ID, true).
		Update("import_pending", false)
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}
	if result.RowsAffected > 0 {
		s.goResolve(up.ID)
		setFlash(w, Flash{Category: successKey, Title: fmt.Sprintf("Importing %d SBOM packages", up.PackageCount)})
	}
	s.redirect(w, r, fmt.Sprintf("/sboms/%d", up.ID))
}

func (s *Server) sbomResolve(w http.ResponseWriter, r *http.Request) {
	up, ok := loadByID[db.SBOMUpload](s, w, r)
	if !ok {
		return
	}
	if up.ImportPending {
		http.Error(w, "confirm SBOM import before resolving repositories", http.StatusConflict)
		return
	}
	s.goResolve(up.ID)
	s.redirect(w, r, fmt.Sprintf("/sboms/%d", up.ID))
}

// goResolve launches resolveSBOMPackages. Indirected so tests can run it
// synchronously and avoid racing the in-memory database teardown.
func (s *Server) goResolve(uploadID uint) {
	if s.resolveSync {
		s.resolveSBOMPackages(uploadID)
		return
	}
	go s.resolveSBOMPackages(uploadID)
}

func (s *Server) sbomDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Delete the upload's packages explicitly inside one transaction rather
	// than leaning on the SBOMUpload.Packages ON DELETE CASCADE: sqlite's
	// foreign_keys pragma is per-connection and enforced on only one pooled
	// connection, so the cascade silently no-ops on most serving connections
	// and orphans the package rows (same reason repoDelete deletes children
	// by hand).
	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("sbom_upload_id = ?", id).Delete(&db.SBOMPackage{}).Error; err != nil {
			return err
		}
		return tx.Delete(&db.SBOMUpload{}, id).Error
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, "/sboms")
}

func (s *Server) autoResolveGeneratedSBOM(scan *db.Scan) {
	if scan.Status != db.ScanDone || scan.SubPath != "" {
		return
	}
	var uploads []db.SBOMUpload
	if err := s.DB.Select("id").Where("scan_id = ? AND origin = ? AND current = ?", scan.ID, db.SBOMOriginGenerated, true).Find(&uploads).Error; err != nil {
		s.Log.Error("find generated SBOM", "scan", scan.ID, "err", err)
		return
	}
	for _, upload := range uploads {
		s.goResolve(upload.ID)
	}
}

// Uploaded snapshots triage direct dependencies; generated ones only link repositories.
func (s *Server) resolveSBOMPackages(uploadID uint) {
	ctx, cancel := context.WithTimeout(context.Background(), sbomResolveTimeout)
	defer cancel()

	var upload db.SBOMUpload
	if err := s.DB.First(&upload, uploadID).Error; err != nil || upload.ImportPending {
		return
	}
	var pkgs []db.SBOMPackage
	if err := s.DB.Where("sbom_upload_id = ? AND source_repository_id IS NULL", uploadID).Order("id").Find(&pkgs).Error; err != nil {
		s.Log.Error("load SBOM packages", "sbom", uploadID, "err", err)
		return
	}
	purls := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		if p.PURL != "" {
			purls = append(purls, p.PURL)
		}
	}
	var resolved map[string]string
	var lookupErr error
	if s.ecosystemsEnrichment && len(purls) > 0 {
		resolved, lookupErr = s.resolvePURLs(ctx, purls)
	}

	for i := range pkgs {
		p := &pkgs[i]
		if p.PURL == "" {
			s.recordSBOMResolveError(p, noPURLError)
			continue
		}
		if !s.ecosystemsEnrichment {
			// Whatever an earlier enabled run concluded is more precise than
			// "the operator turned enrichment off", so a re-resolve with the
			// setting flipped keeps it instead of overwriting it.
			if p.ResolveError == "" {
				s.recordSBOMResolveError(p, ecosystemsDisabled)
			}
			continue
		}
		if lookupErr != nil {
			s.recordSBOMResolveError(p, "repository lookup failed: "+lookupErr.Error())
			continue
		}
		repoURL := resolved[p.PURL]
		if repoURL == "" {
			s.recordSBOMResolveError(p, "no repository_url for purl")
			continue
		}
		input, err := ParseRepoInput(repoURL)
		if err != nil {
			s.recordSBOMResolveError(p, err.Error())
			continue
		}
		triage := upload.Origin == db.SBOMOriginUploaded && p.Scope != sbom.ScopeTransitive
		repo, _, err := s.createOrTriageRepo(ctx, input, "", triage)
		if err != nil {
			s.recordSBOMResolveError(p, err.Error())
			continue
		}
		if err := s.DB.Model(p).Updates(map[string]any{"source_repository_id": repo.ID, "resolve_error": ""}).Error; err != nil {
			s.Log.Error("link SBOM package", "package", p.ID, "err", err)
		}
	}
}

func (s *Server) recordSBOMResolveError(pkg *db.SBOMPackage, reason string) {
	if err := s.DB.Model(pkg).Update("resolve_error", reason).Error; err != nil {
		s.Log.Error("save SBOM resolution error", "package", pkg.ID, "err", err)
	}
}

// purlType returns the ecosystem segment of a Package URL (the bit between
// "pkg:" and the first "/").
func purlType(purl string) string {
	const prefix = "pkg:"
	if !strings.HasPrefix(purl, prefix) {
		return ""
	}
	rest := purl[len(prefix):]
	if i := strings.IndexByte(rest, '/'); i > 0 {
		return rest[:i]
	}
	return rest
}
