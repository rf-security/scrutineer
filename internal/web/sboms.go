package web

import (
	"context"
	"errors"
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
	q, sort := sbomListOrder(q, r.URL.Query().Get("sort"))

	var total int64
	q.Count(&total)
	page := paginate(r, total)
	var rows []db.SBOMUpload
	q.Limit(perPage).Offset((page.N - 1) * perPage).Find(&rows)
	s.render(w, r, "sboms.html", map[string]any{"SBOMs": rows, "Page": page, "Sort": sort})
}

// sbomListOrder applies the SBOM index's sort token and returns the
// effective token. Shared by the HTML index and GET /api/v1/ui/sboms.
func sbomListOrder(q *gorm.DB, token string) (*gorm.DB, string) {
	sortCol, dir := splitSort(token)
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
	return q, joinSort(sortCol, dir)
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

	up, err := s.createSBOMUpload(data, header.Filename)
	if err != nil {
		var perr sbomParseError
		if errors.As(err, &perr) {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.redirect(w, r, fmt.Sprintf("/sboms/%d", up.ID))
}

// sbomParseError is an unparseable SBOM document (a 422, not a 500).
type sbomParseError struct{ err error }

func (e sbomParseError) Error() string { return "parse SBOM: " + e.err.Error() }
func (e sbomParseError) Unwrap() error { return e.err }

// createSBOMUpload parses an uploaded document and stores it, with its
// packages, as an upload awaiting import confirmation. Shared by the HTML
// upload and POST /api/v1/ui/sboms.
func (s *Server) createSBOMUpload(data []byte, filename string) (db.SBOMUpload, error) {
	doc, err := sbom.Parse(data)
	if err != nil {
		return db.SBOMUpload{}, sbomParseError{err}
	}

	up := db.SBOMUpload{
		Name:          firstNonEmpty(doc.Document.Name, filename),
		Filename:      filename,
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
		return db.SBOMUpload{}, err
	}
	return up, nil
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
		q := s.sbomFindingsQuery(repoIDs, r.URL.Query().Get("severity"), r.URL.Query().Get("category"))
		q, sortCol, dir = sbomFindingsOrder(q, sortCol, dir)
		q.Model(&db.Finding{}).Count(&findingsTotal)
		q.Limit(tabRowCap).Find(&findings)

		advQ := s.sbomAdvisoriesQuery(repoIDs)
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

// sbomFindingsQuery selects the open, curated findings of an SBOM's resolved
// repositories, optionally narrowed by severity and CWE category. Shared by
// sbomShow and GET /api/v1/ui/sboms/{id}/findings.
func (s *Server) sbomFindingsQuery(repoIDs []uint, severity, category string) *gorm.DB {
	// Deep-dive findings only — the SBOM "Findings" tab is a
	// downstream-impact view, where lint output from per-repo scanners
	// (zizmor, semgrep) would be misleading at this level.
	q := s.DB.Where("repository_id IN ? AND status NOT IN ?", repoIDs, db.ClosedFindingLifecycles).
		Where("scan_id IN (?)", findingsScanIDs(s.DB))
	if severity != "" {
		q = q.Where("severity = ?", severity)
	}
	if category != "" {
		q = applyCWECategoryFilter(q, category)
	}
	return q
}

// sbomFindingsOrder applies the SBOM Findings tab's sort and returns the
// effective column and direction.
func sbomFindingsOrder(q *gorm.DB, sortCol, dir string) (*gorm.DB, string, string) {
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
	return q, sortCol, dir
}

// sbomAdvisoriesQuery selects the published (not withdrawn) advisories of an
// SBOM's resolved repositories.
func (s *Server) sbomAdvisoriesQuery(repoIDs []uint) *gorm.DB {
	return s.DB.Where("repository_id IN ? AND withdrawn_at IS NULL", repoIDs)
}

// sbomConfirm starts repository resolution for a newly parsed SBOM. The
// conditional update makes a repeated click harmless: only the first request
// changes the pending state and launches the background resolver.
func (s *Server) sbomConfirm(w http.ResponseWriter, r *http.Request) {
	up, ok := loadByID[db.SBOMUpload](s, w, r)
	if !ok {
		return
	}
	started, err := s.confirmSBOMImport(up.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if started {
		setFlash(w, Flash{Category: successKey, Title: fmt.Sprintf("Importing %d SBOM packages", up.PackageCount)})
	}
	s.redirect(w, r, fmt.Sprintf("/sboms/%d", up.ID))
}

// confirmSBOMImport clears import_pending and launches the resolver. started
// is false when the import was already confirmed (nothing is launched).
func (s *Server) confirmSBOMImport(id uint) (started bool, err error) {
	result := s.DB.Model(&db.SBOMUpload{}).
		Where("id = ? AND import_pending = ?", id, true).
		Update("import_pending", false)
	if result.Error != nil {
		return false, result.Error
	}
	if result.RowsAffected == 0 {
		return false, nil
	}
	s.goResolve(id)
	return true, nil
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
//
// It publishes an `sbom` event when the run starts and when it finishes, so
// the UI updates resolution progress live.
func (s *Server) goResolve(uploadID uint) {
	s.publishSBOMProgress(uploadID, false)
	run := func() {
		s.resolveSBOMPackages(uploadID)
		s.publishSBOMProgress(uploadID, true)
	}
	if s.resolveSync {
		run()
		return
	}
	go run()
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
	if err := s.deleteSBOM(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, "/sboms")
}

// deleteSBOM removes an upload and its packages in one transaction.
func (s *Server) deleteSBOM(id int) error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("sbom_upload_id = ?", id).Delete(&db.SBOMPackage{}).Error; err != nil {
			return err
		}
		return tx.Delete(&db.SBOMUpload{}, id).Error
	})
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
