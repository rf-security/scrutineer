package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// Tab data endpoints of RepoDetail (02 #30-#37, #43). Each tab is a paged
// envelope so the SPA renders every tab with one DataTable shape.

const (
	uiRepoTabPageSize   = 50
	uiRepoLatestScanCap = 200
	uiLatestParam       = "latest"
	uiParamOn           = "1"
)

// pageSlice returns one page of an in-memory list.
func pageSlice[T any](items []T, p listPage) []T {
	start := min(p.offset(), len(items))
	end := min(start+p.PageSize, len(items))
	return items[start:end]
}

// parseTabPage parses the tab's page params with the tab default size.
func parseTabPage(w http.ResponseWriter, r *http.Request) (listPage, bool) {
	p, err := parseListPageDefault(r, uiRepoTabPageSize)
	if err != nil {
		uiBadParam(w, err.Error())
		return p, false
	}
	return p, true
}

// ---------------------------------------------------------------- #30 findings

// uiRepoFindingParams are the validated filters of the repo Findings tab.
type uiRepoFindingParams struct {
	page     listPage
	scanners bool
	status   string
	severity string
	category string
	sort     string
}

func parseUIRepoFindingParams(r *http.Request) (uiRepoFindingParams, error) {
	var p uiRepoFindingParams
	var err error
	if p.page, err = parseListPageDefault(r, uiRepoTabPageSize); err != nil {
		return p, err
	}
	q := r.URL.Query()
	p.scanners = q.Get("scanners") == uiParamOn
	p.status = q.Get(statusKey)
	if p.status != "" && p.status != allStatusValue && !slices.Contains(db.FindingLifecycles, db.FindingLifecycle(p.status)) {
		return p, fmt.Errorf("invalid status filter %q", p.status)
	}
	p.severity = q.Get("severity")
	if p.severity != "" && !slices.Contains(db.SeverityLevels, p.severity) {
		return p, fmt.Errorf("invalid severity filter %q", p.severity)
	}
	p.category = q.Get("category")
	if p.category != "" && p.category != UncategorizedCWE && !slices.Contains(CWECategories(), p.category) {
		return p, fmt.Errorf("invalid category filter %q", p.category)
	}
	p.sort = q.Get("sort")
	return p, nil
}

// where applies every filter except the scanner bucket.
func (p uiRepoFindingParams) where(q *gorm.DB, r *http.Request, repoID uint) *gorm.DB {
	q = q.Where("repository_id = ?", repoID)
	q = applyFindingStatusFilter(q, p.status)
	if p.severity != "" {
		q = q.Where("severity = ?", p.severity)
	}
	if p.category != "" {
		q = applyCWECategoryFilter(q, p.category)
	}
	if search := strings.TrimSpace(r.URL.Query().Get("q")); search != "" {
		like := "%" + search + "%"
		q = q.Where("LOWER(title) LIKE LOWER(?) OR LOWER(location) LIKE LOWER(?) OR LOWER(cwe) LIKE LOWER(?)", like, like, like)
	}
	return q
}

// uiRepoFindingOrder is the repo tab's order: severity first (the HTML tab's
// order) unless a list sort token asks otherwise.
func uiRepoFindingOrder(q *gorm.DB, token string) *gorm.DB {
	col, dir := splitSort(token)
	switch col {
	case defaultSort:
		return q.Order(orderByExpr("id", dir, true))
	case uiKeyTitle:
		return q.Order(orderByExpr(uiKeyTitle, dir, false)).Order("id desc")
	case statusKey:
		return q.Order(orderByExpr("status", dir, false)).Order("id desc")
	case uiKeyCWE:
		return q.Order(orderByExpr(uiKeyCWE, dir, false)).Order("id desc")
	default:
		return q.Order(severityOrder).Order("id desc")
	}
}

func (s *Server) uiRepoFindings(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	p, err := parseUIRepoFindingParams(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	bucket := nonScannerScanFilter
	if p.scanners {
		bucket = scannerScanFilter
	}
	var total, scannerTotal, missed int64
	p.where(s.DB.Model(&db.Finding{}), r, repo.ID).Where(bucket).Count(&total)
	p.where(s.DB.Model(&db.Finding{}), r, repo.ID).Where(scannerScanFilter).Count(&scannerTotal)
	p.where(s.DB.Model(&db.Finding{}), r, repo.ID).Where(bucket).Where("missed_count > 0").Count(&missed)
	var findings []db.Finding
	q := uiRepoFindingOrder(p.where(s.DB.Model(&db.Finding{}), r, repo.ID).Where(bucket), p.sort)
	if err := q.Limit(p.page.PageSize).Offset(p.page.offset()).Find(&findings).Error; err != nil {
		uiInternal(w, err)
		return
	}
	scanCommit, scanSkill := s.uiFindingScanInfo(findings)
	writeListWith(w, s.uiRepoFindingRows(repo.ID, findings), total, p.page, map[string]any{
		"counts":      map[string]int64{"missed": missed, "scanners": scannerTotal},
		"scan_commit": scanCommit,
		"scan_skill":  scanSkill,
	})
}

// uiFindingScanInfo maps each finding's producing scan to its commit and
// skill (the HTML tab's ScanCommit/ScanSkill maps), keyed by scan id.
func (s *Server) uiFindingScanInfo(findings []db.Finding) (commits, skills map[string]string) {
	commits, skills = map[string]string{}, map[string]string{}
	ids := make([]uint, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.ScanID)
	}
	if len(ids) == 0 {
		return commits, skills
	}
	var rows []db.Scan
	s.DB.Select("id", "skill_name", uiKeyCommit).Where("id IN ?", ids).Find(&rows)
	for _, row := range rows {
		key := fmt.Sprint(row.ID)
		commits[key] = row.Commit
		skills[key] = row.SkillName
	}
	return commits, skills
}

// ---------------------------------------------------------------- #31 scans

func (s *Server) uiRepoScans(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	latest := loadRepoLatestScansSelect(s.DB, repo.ID, "s.id, s.status")
	active, paused := s.repoScanActionCounts(repo.ID)
	counts := map[string]int64{"active": active, "paused": paused, "failed": int64(countFailedScans(latest))}
	switch v := r.URL.Query().Get(uiLatestParam); v {
	case "", uiParamOn:
		s.uiRepoLatestScans(w, latest, counts)
	case "0":
		s.uiRepoScanHistory(w, r, repo.ID, counts)
	default:
		uiBadParam(w, fmt.Sprintf("latest must be 0 or 1, got %q", v))
	}
}

// uiRepoLatestScans writes the latest attempt per (skill, sub_path,
// focus_area), capped; total reports the whole set so the SPA can fall back
// to latest=0 paging.
func (s *Server) uiRepoLatestScans(w http.ResponseWriter, latest []db.Scan, counts map[string]int64) {
	ids := make([]uint, 0, min(len(latest), uiRepoLatestScanCap))
	for i := 0; i < len(latest) && i < uiRepoLatestScanCap; i++ {
		ids = append(ids, latest[i].ID)
	}
	rows := []map[string]any{}
	if len(ids) > 0 {
		var err error
		rows, err = s.uiScanRows(s.DB.Model(&db.Scan{}).Where("scans.id IN ?", ids).Order("scans.id desc"))
		if err != nil {
			uiInternal(w, err)
			return
		}
	}
	writeListWith(w, rows, int64(len(latest)), listPage{Page: 1, PageSize: uiRepoLatestScanCap}, map[string]any{"counts": counts})
}

// uiRepoScanHistory is the full history: the /ui/scans list query pinned to
// this repository.
func (s *Server) uiRepoScanHistory(w http.ResponseWriter, r *http.Request, repoID uint, counts map[string]int64) {
	p, err := parseUIScanListParams(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	p.repositoryID = repoID
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
	writeListWith(w, rows, total, p.page, map[string]any{"counts": counts})
}

// ---------------------------------------------------------------- #32 dependencies

func (s *Server) uiRepoDependencies(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	p, ok := parseTabPage(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	hiddenTypes := []string{db.DependencyDev, db.DependencyTest, db.DependencyBuild}
	var hidden int64
	s.DB.Model(&db.Dependency{}).Where("repository_id = ? AND dependency_type IN ?", repo.ID, hiddenTypes).Count(&hidden)
	q := s.DB.Model(&db.Dependency{}).Where("repository_id = ?", repo.ID)
	if query.Get("all") != uiParamOn {
		q = q.Where("dependency_type NOT IN ?", hiddenTypes)
	}
	if eco := query.Get("ecosystem"); eco != "" {
		q = q.Where("ecosystem = ?", eco)
	}
	if search := strings.TrimSpace(query.Get("q")); search != "" {
		q = q.Where("LOWER(name) LIKE LOWER(?)", "%"+search+"%")
	}
	var total int64
	q.Count(&total)
	var deps []db.Dependency
	if err := q.Order("ecosystem, name, manifest_kind desc").Limit(p.PageSize).Offset(p.offset()).Find(&deps).Error; err != nil {
		uiInternal(w, err)
		return
	}
	groups := make([]DepGroup, len(deps))
	for i, d := range deps {
		groups[i] = DepGroup{Dependency: d}
	}
	known := s.lookupKnownPURLs(groups)
	items := make([]map[string]any, len(deps))
	for i, d := range deps {
		items[i] = uiDependencyRow(d, known)
	}
	commit := ""
	if total > 0 {
		commit = s.latestDepsCommit(repo.ID)
	}
	writeListWith(w, items, total, p, map[string]any{"hidden": hidden, uiKeyCommit: commit})
}

// uiDependencyRow is one UIDependency. known maps PURLs to the repository
// that publishes them (lookupKnownPURLs).
func uiDependencyRow(d db.Dependency, known map[string]uint) map[string]any {
	var knownRepo any
	if id, ok := known[d.PURL]; ok && d.PURL != "" {
		knownRepo = id
	} else if base, _, cut := strings.Cut(d.PURL, "?"); cut {
		if id, ok := known[base]; ok {
			knownRepo = id
		}
	}
	return map[string]any{
		"id": d.ID, uiKeyName: d.Name, "ecosystem": d.Ecosystem, "version": d.Requirement,
		"unresolved": d.RequirementUnresolved, "resolution": d.RequirementResolution, "type": d.DependencyType,
		"manifests":           []map[string]string{{"path": d.ManifestPath, "kind": d.ManifestKind}},
		"purl":                d.PURL,
		"known_repository_id": knownRepo,
	}
}

// ---------------------------------------------------------------- #33 inventory tabs

func (s *Server) uiRepoPackages(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	p, ok := parseTabPage(w, r)
	if !ok {
		return
	}
	var total int64
	s.DB.Model(&db.Package{}).Where("repository_id = ?", repo.ID).Count(&total)
	var rows []db.Package
	s.DB.Where("repository_id = ?", repo.ID).Order("dependent_repos desc, downloads desc").
		Limit(p.PageSize).Offset(p.offset()).Find(&rows)
	subPaths := map[uint]string{}
	var subs []db.Subproject
	s.DB.Select("id", "path").Where("repository_id = ?", repo.ID).Find(&subs)
	for _, sp := range subs {
		subPaths[sp.ID] = sp.Path
	}
	items := make([]packageResponse, 0, len(rows))
	for _, pk := range rows {
		resp := packageResponse{
			ID: pk.ID, Name: pk.Name, Ecosystem: pk.Ecosystem, PURL: pk.PURL, LatestVersion: pk.LatestVersion,
			Downloads: pk.Downloads, DependentPackages: pk.DependentPackages, DependentRepos: pk.DependentRepos,
			RegistryURL: pk.RegistryURL, LatestReleaseAt: pk.LatestReleaseAt, RiskFlags: db.PackageRiskFlags(pk.RiskFlags),
		}
		if pk.SubprojectID != nil {
			resp.SubPath = subPaths[*pk.SubprojectID]
		}
		items = append(items, resp)
	}
	writeList(w, items, total, p)
}

func (s *Server) uiRepoDependents(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	p, ok := parseTabPage(w, r)
	if !ok {
		return
	}
	var total int64
	s.DB.Model(&db.Dependent{}).Where("repository_id = ?", repo.ID).Count(&total)
	var rows []db.Dependent
	s.DB.Where("repository_id = ?", repo.ID).Order("dependent_repos desc").Limit(p.PageSize).Offset(p.offset()).Find(&rows)
	known := s.lookupKnownURLs(rows)
	items := make([]map[string]any, 0, len(rows))
	for _, d := range rows {
		var knownRepo any
		if id, ok := known[d.RepositoryURL]; ok {
			knownRepo = id
		}
		items = append(items, map[string]any{
			"id": d.ID, uiKeyName: d.Name, "ecosystem": d.Ecosystem, "purl": d.PURL, "repository_url": d.RepositoryURL,
			"downloads": d.Downloads, "dependent_repos": d.DependentRepos, "registry_url": d.RegistryURL,
			"latest_version": d.LatestVersion, "known_repository_id": knownRepo,
		})
	}
	writeList(w, items, total, p)
}

func (s *Server) uiRepoAdvisories(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	p, ok := parseTabPage(w, r)
	if !ok {
		return
	}
	var total int64
	s.DB.Model(&db.Advisory{}).Where("repository_id = ?", repo.ID).Count(&total)
	var rows []db.Advisory
	s.DB.Where("repository_id = ?", repo.ID).Order("cvss_score desc").Limit(p.PageSize).Offset(p.offset()).Find(&rows)
	audits := s.latestAdvisoryAuditStatuses(rows)
	items := make([]map[string]any, 0, len(rows))
	for _, a := range rows {
		status := audits[a.ID]
		cert := ""
		if status == "fixed" {
			cert = fmt.Sprintf("/advisories/%d/certificate.json", a.ID)
		}
		items = append(items, map[string]any{
			"id": a.ID, "uuid": a.UUID, uiKeyURL: a.URL, uiKeyTitle: a.Title, "severity": a.Severity,
			"cvss_score": a.CVSSScore, "classification": a.Classification, uiKeyPackages: a.Packages,
			"published_at": a.PublishedAt, "withdrawn_at": a.WithdrawnAt,
			"audit_status": status, "certificate_url": cert,
		})
	}
	writeList(w, items, total, p)
}

func (s *Server) uiRepoMaintainers(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	p, ok := parseTabPage(w, r)
	if !ok {
		return
	}
	rows := s.repoMaintainers(repo.ID)
	slices.SortFunc(rows, func(a, b db.Maintainer) int { return strings.Compare(a.Login, b.Login) })
	items := make([]map[string]any, 0, len(rows))
	for _, m := range pageSlice(rows, p) {
		items = append(items, map[string]any{
			"id": m.ID, "login": m.Login, uiKeyName: m.Name, "email": m.Email, statusKey: string(m.Status),
			"notes": m.Notes, "do_not_contact": m.DoNotContact,
		})
	}
	writeList(w, items, int64(len(rows)), p)
}

func (s *Server) uiRepoAlternatives(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	p, ok := parseTabPage(w, r)
	if !ok {
		return
	}
	rows, err := loadPackageAlternatives(s.DB, repo.ID)
	if err != nil {
		uiInternal(w, err)
		return
	}
	writeListWith(w, packageAlternativeResponses(pageSlice(rows, p)), int64(len(rows)), p, map[string]any{
		"show": showPackageAlternatives(repo, rows),
	})
}

func (s *Server) uiRepoExpected(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	p, ok := parseTabPage(w, r)
	if !ok {
		return
	}
	set := s.uiRepoExpectedMatches(repo.ID)
	items := make([]map[string]any, 0, len(set.Expected))
	for _, e := range pageSlice(set.Expected, p) {
		items = append(items, uiExpectedRow(e))
	}
	writeListWith(w, items, int64(len(set.Expected)), p, map[string]any{
		"matched": set.MatchedTotal, "finding_total": set.FindingTotal, "true_positive_findings": set.TruePositiveFindings,
	})
}

// uiExpectedRow is one Benchmark tab row.
func uiExpectedRow(e expectedFindingStatus) map[string]any {
	status := "missed"
	var matchedID any
	if e.Matched {
		status = "matched"
		matchedID = e.FindingID
	}
	return map[string]any{
		"id": e.Expected.ID, repositoryIDKey: e.Expected.RepositoryID, "file": e.Expected.File, uiKeyCWE: e.Expected.CWE,
		"cve": e.Expected.CVE, "note": e.Expected.Note, statusKey: status, "matched_finding_id": matchedID,
	}
}

func (s *Server) uiRepoSubprojects(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	p, ok := parseTabPage(w, r)
	if !ok {
		return
	}
	view := s.loadRepoSubprojectView(repo.ID)
	items := make([]map[string]any, 0, len(view.Rows))
	for _, sub := range pageSlice(view.Rows, p) {
		items = append(items, uiSubprojectRow(sub, view.ScanCount[sub.ScanSubPath()]))
	}
	writeList(w, items, int64(len(view.Rows)), p)
}

// uiSubprojectRow is one Subprojects tab row (and the subproject object of
// the subproject detail).
func uiSubprojectRow(sub db.Subproject, scanCount int) map[string]any {
	return map[string]any{
		"id": sub.ID, repositoryIDKey: sub.RepositoryID, "path": sub.Path, uiKeyName: sub.Name, "kind": sub.Kind,
		"description": sub.Description, "disclosure_channel": sub.DisclosureChannel, "sub_path": sub.ScanSubPath(),
		"scan_count": scanCount,
	}
}

func (s *Server) uiRepoCompliance(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r, "baseline_level")
	if !ok {
		return
	}
	p, ok := parseTabPage(w, r)
	if !ok {
		return
	}
	var total int64
	s.DB.Model(&db.ComplianceControl{}).Where("repository_id = ?", repo.ID).Count(&total)
	var rows []db.ComplianceControl
	s.DB.Where("repository_id = ?", repo.ID).Order("level, control_id").Limit(p.PageSize).Offset(p.offset()).Find(&rows)
	items := make([]map[string]any, 0, len(rows))
	for _, c := range rows {
		items = append(items, map[string]any{
			"id": c.ID, "control_id": c.ControlID, "level": c.Level, statusKey: c.Status,
			"details": c.Details, "source": c.Source, uiEventScanIDKey: c.ScanID,
		})
	}
	writeListWith(w, items, total, p, map[string]any{"level": fmt.Sprintf("L%d", repo.BaselineLevel)})
}

// ---------------------------------------------------------------- #34-#37 single-object tabs

func (s *Server) uiRepoThreatModel(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	tm := s.loadThreatModelScan(s.loadUIRepoPrimary(repo.ID))
	report := scanThreatModelReport(tm)
	if tm == nil || report == nil {
		uiNotFound(w, "threat model")
		return
	}
	writeUIJSON(w, http.StatusOK, map[string]any{"report": report, uiKeyCommit: tm.Commit, uiEventScanIDKey: tm.ID, "skill_name": tm.SkillName})
}

func (s *Server) uiRepoWorkbench(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r, "threat_model")
	if !ok {
		return
	}
	tm := s.loadThreatModelScan(s.loadUIRepoPrimary(repo.ID))
	wb := loadWorkbench(s.DB, &repo, workbenchSeed(tm))
	ids := make([]uint, len(wb.Runs))
	for i, sc := range wb.Runs {
		ids[i] = sc.ID
	}
	runs := []map[string]any{}
	if len(ids) > 0 {
		var err error
		runs, err = s.uiScanRows(s.DB.Model(&db.Scan{}).Where("scans.id IN ?", ids).Order("scans.id desc"))
		if err != nil {
			uiInternal(w, err)
			return
		}
	}
	var diff any
	if len(wb.Runs) > 1 {
		diff = uiWorkbenchDiff(wb.Diff)
	}
	writeUIJSON(w, http.StatusOK, map[string]any{uiKeyModel: wb.Model, "has_override": wb.HasOverride, "runs": runs, "diff": diff})
}

// uiWorkbenchDiff renders empty buckets as [] rather than null.
func uiWorkbenchDiff(d WorkbenchDiff) WorkbenchDiff {
	for _, b := range []*[]DiffRow{&d.NowReported, &d.NowSuppressed, &d.ReasonChanged} {
		if *b == nil {
			*b = []DiffRow{}
		}
	}
	return d
}

func (s *Server) uiRepoScanConfig(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r, "scan_config")
	if !ok {
		return
	}
	writeUIJSON(w, http.StatusOK, uiScanConfigView(repo, nil))
}

// uiScanConfigView is the ScanConfigView body; changed is set by the
// ignored-path writes.
func uiScanConfigView(repo db.Repository, changed *bool) map[string]any {
	paths := repoIgnoredPaths(repo)
	if paths == nil {
		paths = []string{}
	}
	out := map[string]any{"yaml": repo.ScanConfig, "ignored_paths": paths, "set": strings.TrimSpace(repo.ScanConfig) != ""}
	if changed != nil {
		out["changed"] = *changed
	}
	return out
}

func (s *Server) uiRepoMetadata(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r, "metadata")
	if !ok {
		return
	}
	if strings.TrimSpace(repo.Metadata) == "" || !json.Valid([]byte(repo.Metadata)) {
		uiNotFound(w, "metadata")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(cacheControlHeader, noStore)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(repo.Metadata))
}

// ---------------------------------------------------------------- #43 subproject

// uiLoadSubproject loads {sub} on repoID with the UI envelope on failure.
func (s *Server) uiLoadSubproject(w http.ResponseWriter, r *http.Request, repoID uint) (db.Subproject, bool) {
	subID, ok := uiPathID(w, r, "sub")
	if !ok {
		return db.Subproject{}, false
	}
	var sub db.Subproject
	if err := s.DB.Where("id = ? AND repository_id = ?", subID, repoID).First(&sub).Error; err != nil {
		uiDBError(w, err, "subproject")
		return sub, false
	}
	return sub, true
}

func (s *Server) uiSubprojectDetail(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	sub, ok := s.uiLoadSubproject(w, r, repo.ID)
	if !ok {
		return
	}
	p, ok := parseTabPage(w, r)
	if !ok {
		return
	}
	writeUIJSON(w, http.StatusOK, s.uiSubprojectView(repo, sub, p))
}

// uiSubprojectView is subprojectShow's data: findings scoped by sub_path
// (paged), packages and advisories attributed to it (when attribution is on)
// and its own vs effective disclosure channel.
func (s *Server) uiSubprojectView(repo db.Repository, sub db.Subproject, p listPage) map[string]any {
	q := func() *gorm.DB {
		q := s.DB.Model(&db.Finding{}).Where("repository_id = ?", repo.ID)
		if subPath := sub.ScanSubPath(); subPath == "" {
			return q.Where("sub_path = '' OR sub_path IS NULL")
		}
		return q.Where("sub_path = ?", sub.ScanSubPath())
	}
	var total int64
	q().Count(&total)
	var findings []db.Finding
	q().Order("id desc").Limit(p.PageSize).Offset(p.offset()).Find(&findings)
	packages := []map[string]any{}
	advisories := []map[string]any{}
	if s.MonorepoAttribution {
		var pkgs []db.Package
		s.DB.Where("subproject_id = ?", sub.ID).Order("downloads desc").Find(&pkgs)
		for _, pk := range pkgs {
			packages = append(packages, map[string]any{
				"id": pk.ID, uiKeyName: pk.Name, "ecosystem": pk.Ecosystem, "purl": pk.PURL,
				"latest_version": pk.LatestVersion, "downloads": pk.Downloads, "registry_url": pk.RegistryURL,
			})
		}
		var advs []db.Advisory
		s.DB.Where("subproject_id = ?", sub.ID).Order("published_at desc").Find(&advs)
		for _, a := range advs {
			advisories = append(advisories, map[string]any{
				"id": a.ID, "uuid": a.UUID, uiKeyURL: a.URL, uiKeyTitle: a.Title, "severity": a.Severity,
				"cvss_score": a.CVSSScore, "published_at": a.PublishedAt, "withdrawn_at": a.WithdrawnAt,
			})
		}
	}
	view := s.loadRepoSubprojectView(repo.ID)
	return map[string]any{
		"subproject": uiSubprojectRow(sub, view.ScanCount[sub.ScanSubPath()]),
		"repository": map[string]any{"id": repo.ID, uiKeyName: repo.Name},
		uiKeyFindings: map[string]any{
			"items": s.uiRepoFindingRows(repo.ID, findings), "total": total, "page": p.Page, "page_size": p.PageSize,
		},
		uiKeyPackages: packages,
		"advisories":  advisories,
		"disclosure_channel": map[string]string{
			"own": sub.DisclosureChannel, "effective": db.EffectiveDisclosureChannel(s.DB, repo.ID, sub.Path),
		},
		"attribution": map[string]bool{"enabled": s.MonorepoAttribution},
	}
}
