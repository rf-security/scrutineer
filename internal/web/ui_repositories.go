package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// registerUIRepositoryRoutes registers the repository and code routes of the /api/v1/ui surface
// (02-api-plan.md section 3.3 #28-#55, minus #38 which WP-API-4 owns). Handlers
// live in the ui_repositories*.go siblings and ui_code.go; every route is
// documented in openapi.yaml between the "# --- ui:repositories begin/end ---"
// markers. TestOpenAPICoversRegisteredAPIRoutes fails on any undocumented route.
func (s *Server) registerUIRepositoryRoutes(mux *http.ServeMux) {
	// List, add, import (#28, #48-#51).
	mux.HandleFunc("GET /ui/repositories", s.uiRepoList)
	mux.HandleFunc("POST /ui/repositories", s.uiRepoCreate)
	mux.HandleFunc("GET /ui/repositories/branches", s.uiRepoBranches)
	mux.HandleFunc("POST /ui/repositories/bulk", s.uiRepoBulkCreate)
	mux.HandleFunc("POST /ui/repositories/org/preview", s.uiOrgImportPreview)
	mux.HandleFunc("POST /ui/repositories/org", s.uiOrgImport)
	mux.HandleFunc("POST /ui/investigations", s.uiInvestigationCreate)
	mux.HandleFunc("POST /ui/dependencies/{id}/import", s.uiDependencyImport)
	mux.HandleFunc("POST /ui/dependents/{id}/import", s.uiDependentImport)

	// Detail, settings autosave (#29, #39).
	mux.HandleFunc("GET /ui/repositories/{id}", s.uiRepoDetail)
	mux.HandleFunc("PATCH /ui/repositories/{id}", s.uiRepoPatch)

	// Tab data (#30-#37).
	mux.HandleFunc("GET /ui/repositories/{id}/findings", s.uiRepoFindings)
	mux.HandleFunc("GET /ui/repositories/{id}/scans", s.uiRepoScans)
	mux.HandleFunc("GET /ui/repositories/{id}/dependencies", s.uiRepoDependencies)
	mux.HandleFunc("GET /ui/repositories/{id}/packages", s.uiRepoPackages)
	mux.HandleFunc("GET /ui/repositories/{id}/dependents", s.uiRepoDependents)
	mux.HandleFunc("GET /ui/repositories/{id}/advisories", s.uiRepoAdvisories)
	mux.HandleFunc("GET /ui/repositories/{id}/maintainers", s.uiRepoMaintainers)
	mux.HandleFunc("GET /ui/repositories/{id}/alternatives", s.uiRepoAlternatives)
	mux.HandleFunc("GET /ui/repositories/{id}/expected", s.uiRepoExpected)
	mux.HandleFunc("GET /ui/repositories/{id}/subprojects", s.uiRepoSubprojects)
	mux.HandleFunc("GET /ui/repositories/{id}/compliance", s.uiRepoCompliance)
	mux.HandleFunc("GET /ui/repositories/{id}/threat-model", s.uiRepoThreatModel)
	mux.HandleFunc("GET /ui/repositories/{id}/workbench", s.uiRepoWorkbench)
	mux.HandleFunc("GET /ui/repositories/{id}/scan-config", s.uiRepoScanConfig)
	mux.HandleFunc("GET /ui/repositories/{id}/metadata", s.uiRepoMetadata)

	// Tab writes (#40-#44).
	mux.HandleFunc("POST /ui/repositories/{id}/scan-config/ignored-paths", s.uiRepoIgnoredPathAdd)
	mux.HandleFunc("DELETE /ui/repositories/{id}/scan-config/ignored-paths", s.uiRepoIgnoredPathDelete)
	mux.HandleFunc("POST /ui/repositories/{id}/alternatives", s.uiRepoAlternativeCreate)
	mux.HandleFunc("DELETE /ui/repositories/{id}/alternatives/{alternative_id}", s.uiRepoAlternativeDelete)
	mux.HandleFunc("POST /ui/repositories/{id}/expected", s.uiRepoExpectedCreate)
	mux.HandleFunc("DELETE /ui/repositories/{id}/expected/{expected_id}", s.uiRepoExpectedDelete)
	mux.HandleFunc("GET /ui/repositories/{id}/subprojects/{sub}", s.uiSubprojectDetail)
	mux.HandleFunc("PATCH /ui/repositories/{id}/subprojects/{sub}", s.uiSubprojectPatch)

	// Enqueue actions (#45-#47).
	mux.HandleFunc("POST /ui/repositories/{id}/actions/scan", s.uiRepoScanAction)
	mux.HandleFunc("POST /ui/repositories/{id}/actions/scan-all", s.uiRepoScanAllAction)
	mux.HandleFunc("POST /ui/repositories/{id}/actions/verify-all", s.uiRepoVerifyAllAction)
	mux.HandleFunc("POST /ui/repositories/{id}/actions/threat-model-run", s.uiRepoThreatModelRunAction)
	mux.HandleFunc("POST /ui/repositories/{id}/actions/run-skill", s.uiRepoRunSkillAction)
	mux.HandleFunc("POST /ui/repositories/{id}/actions/validate-fix", s.uiRepoValidateFixAction)

	// Code browser (#54, #55).
	mux.HandleFunc("GET /ui/repositories/{id}/blob/{commit}/{path...}", s.uiRepoBlob)
	mux.HandleFunc("GET /ui/repositories/{id}/tree/{commit}/{path...}", s.uiRepoTree)
}

// JSON keys and column names the repository projections repeat.
const (
	uiKeyCommit = "commit"
)

// ---------------------------------------------------------------- RepoRow

// uiRepoListColumns are the scalar repository columns a RepoRow (and the
// RepoDetail scalars) read; the metadata/ecosystems/threat-model/scan-config
// blobs stay out of list queries.
var uiRepoListColumns = []string{
	"id", uiKeyURL, uiKeyName, "full_name", "owner", "description", "default_branch", "languages", "license",
	"stars", "forks", "archived", "pushed_at", "html_url", "health", "clone_error", "disk_bytes",
	"scan_schedule", "upstream_url", "next_scheduled_scan_at", "federation_opt_out_at", uiKeyCreatedAt, "updated_at",
}

// uiStatusScan is the scan that drives a repository's Status badge.
type uiStatusScan struct {
	ID           uint
	RepositoryID uint
	Status       db.ScanStatus
	SkillName    string
}

// uiRepoRows projects the repositories with the given ids as RepoRows, in
// ids order, batch-loading every per-row extra (one query each) the way the
// HTML list does.
func (s *Server) uiRepoRows(ids []uint) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	var exports []repositoryExportRow
	if err := s.repositoryExportQuery().Where("repositories.id IN ?", ids).Scan(&exports).Error; err != nil {
		return nil, err
	}
	var repos []db.Repository
	if err := s.DB.Select(uiRepoListColumns).Where("id IN ?", ids).Find(&repos).Error; err != nil {
		return nil, err
	}
	exportByID := make(map[uint]repositoryExportRow, len(exports))
	for _, e := range exports {
		exportByID[e.ID] = e
	}
	repoByID := make(map[uint]db.Repository, len(repos))
	for _, r := range repos {
		repoByID[r.ID] = r
	}
	statusScans := s.uiRepoStatusScans(ids)
	branches := s.uiRepoBranchTags(ids)
	global, _ := db.GetSetting(s.DB, db.SettingScanSchedule)
	for _, id := range ids {
		repo, ok := repoByID[id]
		if !ok {
			continue
		}
		out = append(out, uiRepoRowFull(exportByID[id], repo, statusScans[id], branches[id], global))
	}
	return out, nil
}

// uiRepoRowFull is uiRepoRow plus the batch-loaded keys.
func uiRepoRowFull(row repositoryExportRow, repo db.Repository, status *uiStatusScan, branches []string, global string) map[string]any {
	m := uiRepoRow(row, repo)
	m["health"] = map[string]any{statusKey: string(repo.Health), "summary": ""}
	m["disk_bytes"] = repo.DiskBytes
	m["findings_total"] = row.FindingsCount
	if status != nil {
		m["status_scan"] = map[string]any{"id": status.ID, statusKey: string(status.Status), "skill_name": status.SkillName}
	} else {
		m["status_scan"] = nil
	}
	if branches == nil {
		branches = []string{}
	}
	m["branches"] = branches
	m["schedule"] = uiRepoSchedule(repo, global)
	return m
}

// uiRepoSchedule is the RepoRow schedule object: the repo's own setting, what
// actually applies (the global default when the repo inherits) and the next
// due time the scheduler recorded.
func uiRepoSchedule(repo db.Repository, global string) map[string]any {
	effective := repo.ScanSchedule
	if effective == "" {
		effective = global
	}
	return map[string]any{"repo": repo.ScanSchedule, "effective": effective, "next_at": repo.NextScheduledScanAt}
}

// uiRepoStatusScans picks each repo's status-badge scan: active work over
// recency, ranked from status as repoList does (keep in lockstep with
// db.StatusPriorityFor). TODO(WP-API-3): share with repoList once its batch
// loaders are extracted from server.go.
func (s *Server) uiRepoStatusScans(ids []uint) map[uint]*uiStatusScan {
	var rows []uiStatusScan
	s.DB.Raw(`
		SELECT id, repository_id, status, skill_name FROM (
			SELECT s.id, s.repository_id, s.status, s.skill_name, ROW_NUMBER() OVER (
				PARTITION BY s.repository_id
				ORDER BY CASE s.status
					WHEN ? THEN 0
					WHEN ? THEN 1
					WHEN ? THEN 2
					ELSE 3
				END, s.id DESC
			) AS rn
			FROM scans s
			WHERE s.repository_id IN ?
		) ranked
		WHERE rn = 1
	`, db.ScanRunning, db.ScanQueued, db.ScanPaused, ids).Scan(&rows)
	out := make(map[uint]*uiStatusScan, len(rows))
	for i := range rows {
		out[rows[i].RepositoryID] = &rows[i]
	}
	return out
}

// uiRepoBranchTags lists the distinct non-default refs scanned per repo.
func (s *Server) uiRepoBranchTags(ids []uint) map[uint][]string {
	var refs []struct {
		RepositoryID uint
		Ref          string
	}
	s.DB.Model(&db.Scan{}).
		Select("DISTINCT repository_id, ref").
		Where("repository_id IN ? AND ref != ''", ids).
		Order("ref").
		Scan(&refs)
	out := map[uint][]string{}
	for _, rr := range refs {
		out[rr.RepositoryID] = append(out[rr.RepositoryID], rr.Ref)
	}
	return out
}

// loadUIRepoRow loads one RepoRow.
func (s *Server) loadUIRepoRow(id uint) (map[string]any, error) {
	rows, err := s.uiRepoRows([]uint{id})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return rows[0], nil
}

// uiLoadRepo loads the {id} repository (scalar columns plus the given extra
// columns), writing the UI 400/404 envelope on failure.
func (s *Server) uiLoadRepo(w http.ResponseWriter, r *http.Request, extra ...string) (db.Repository, bool) {
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return db.Repository{}, false
	}
	var repo db.Repository
	cols := append(append([]string{}, uiRepoListColumns...), extra...)
	if err := s.DB.Select(cols).First(&repo, id).Error; err != nil {
		uiDBError(w, err, uiKeyRepository)
		return repo, false
	}
	return repo, true
}

// ---------------------------------------------------------------- #28 list

// uiRepoListOrder mirrors repoList's sort switch so URL sort tokens are
// portable. TODO(WP-API-3): extract a shared repoListOrderBy from server.go
// once its owner agrees; until then keep the two in lockstep.
func uiRepoListOrder(q *gorm.DB, token string) *gorm.DB {
	col, dir := splitSort(token)
	switch col {
	case uiKeyName:
		return q.Order(orderByExpr(uiKeyName, dir, false))
	case "stars":
		return q.Order(orderByExpr("stars", dir, true))
	case "language":
		return q.Order(orderByExpr("languages", dir, false)).Order(uiKeyName)
	case "size":
		return q.Order(orderByExpr("disk_bytes", dir, true)).Order("updated_at desc")
	case uiKeyFindings:
		return q.Order(orderByExpr("("+deepDiveFindingsCountSQL+")", dir, true)).Order("updated_at desc")
	case "scanned":
		return q.Order(orderByExpr("(SELECT MAX(id) FROM scans WHERE scans.repository_id = repositories.id)", dir, true)).Order("updated_at desc")
	case statusKey:
		return q.Order(orderByExpr("COALESCE((SELECT MIN(status_priority) FROM scans WHERE scans.repository_id = repositories.id), 99)", dir, false)).Order("updated_at desc")
	default:
		return q.Order("updated_at desc")
	}
}

// uiRepoListWhere applies the repo list's q and language filters (repoList's
// WHERE clauses).
func uiRepoListWhere(q *gorm.DB, r *http.Request) *gorm.DB {
	if lang := r.URL.Query().Get("language"); lang != "" {
		q = q.Where("LOWER(', ' || languages || ', ') LIKE LOWER(?)", "%, "+lang+", %")
	}
	if search := strings.TrimSpace(r.URL.Query().Get("q")); search != "" {
		like := "%" + search + "%"
		q = q.Where("LOWER(name) LIKE LOWER(?) OR LOWER(url) LIKE LOWER(?) OR LOWER(full_name) LIKE LOWER(?) OR LOWER(description) LIKE LOWER(?)",
			like, like, like, like)
	}
	return q
}

func (s *Server) uiRepoList(w http.ResponseWriter, r *http.Request) {
	p, err := parseListPage(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	var total int64
	if err := uiRepoListWhere(s.DB.Model(&db.Repository{}), r).Count(&total).Error; err != nil {
		uiInternal(w, err)
		return
	}
	var ids []uint
	q := uiRepoListOrder(uiRepoListWhere(s.DB.Model(&db.Repository{}), r), r.URL.Query().Get("sort"))
	if err := q.Limit(p.PageSize).Offset(p.offset()).Pluck("id", &ids).Error; err != nil {
		uiInternal(w, err)
		return
	}
	rows, err := s.uiRepoRows(ids)
	if err != nil {
		uiInternal(w, err)
		return
	}
	writeListWith(w, rows, total, p, map[string]any{"languages": nonNilStrings(distinctLanguages(s.DB))})
}

// ---------------------------------------------------------------- #29 detail

func (s *Server) uiRepoDetail(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r, "disclosure_channel", "disclosure_channel_at", "federation_opt_out_reason",
		"threat_model", "scan_config", "baseline_level")
	if !ok {
		return
	}
	detail, err := s.uiRepoDetailView(repo)
	if err != nil {
		uiInternal(w, err)
		return
	}
	setETag(w, repo.UpdatedAt)
	writeUIJSON(w, http.StatusOK, detail)
}

// uiRepoPrimary is the light version of repoPrimaryScans: the latest-attempt
// set without blobs, the latest deep-dive and the threat-model scan the Threat
// Model tab renders (a done threat-model scan with a report, else the latest
// done deep-dive with one).
type uiRepoPrimary struct {
	Latest      []db.Scan
	DeepDive    *db.Scan
	ThreatModel *db.Scan
}

func (s *Server) loadUIRepoPrimary(repoID uint) uiRepoPrimary {
	p := uiRepoPrimary{Latest: loadRepoLatestScanRows(s.DB, repoID)}
	var candidates []uint
	for i := range p.Latest {
		sc := &p.Latest[i]
		if sc.SkillName == deepDiveSkillName && p.DeepDive == nil {
			p.DeepDive = sc
		}
		if sc.Status == db.ScanDone && (sc.SkillName == deepDiveSkillName || sc.SkillName == threatModelSkillName) {
			candidates = append(candidates, sc.ID)
		}
	}
	if len(candidates) == 0 {
		return p
	}
	var withReport []uint
	s.DB.Model(&db.Scan{}).Where("id IN ? AND report <> ''", candidates).Pluck("id", &withReport)
	has := map[uint]bool{}
	for _, id := range withReport {
		has[id] = true
	}
	var fallback *db.Scan
	for i := range p.Latest {
		sc := &p.Latest[i]
		if !has[sc.ID] {
			continue
		}
		if sc.SkillName == threatModelSkillName && p.ThreatModel == nil {
			p.ThreatModel = sc
		}
		if sc.SkillName == deepDiveSkillName && fallback == nil {
			fallback = sc
		}
	}
	if p.ThreatModel == nil {
		p.ThreatModel = fallback
	}
	return p
}

// loadThreatModelScan reloads the primary threat-model scan with its report.
func (s *Server) loadThreatModelScan(p uiRepoPrimary) *db.Scan {
	if p.ThreatModel == nil {
		return nil
	}
	var sc db.Scan
	if err := s.DB.Select("id", repositoryIDKey, "skill_name", "sub_path", "status", uiKeyCommit, "report").
		First(&sc, p.ThreatModel.ID).Error; err != nil {
		return nil
	}
	return &sc
}

// repoUnpricedScans counts the repo's scans that used tokens but recorded no
// cost: the worker prices usage from a per-model list price table, and a
// model missing from it (e.g. gpt-daybreak-red-latest) stores cost_usd 0. A
// zero total_cost_usd with a non-zero count means "unknown", not "free".
func repoUnpricedScans(gdb *gorm.DB, repoID uint) int64 {
	var n int64
	gdb.Model(&db.Scan{}).
		Where("repository_id = ? AND COALESCE(cost_usd, 0) = 0 AND COALESCE(input_tokens, 0) + COALESCE(output_tokens, 0) > 0", repoID).
		Count(&n)
	return n
}

func (s *Server) uiRepoDetailView(repo db.Repository) (map[string]any, error) {
	m, err := s.loadUIRepoRow(repo.ID)
	if err != nil {
		return nil, err
	}
	primary := s.loadUIRepoPrimary(repo.ID)
	counts := s.uiRepoCounts(repo, primary)
	m["health"] = map[string]any{statusKey: string(repo.Health), "summary": s.uiRepoHealthSummary(repo)}
	m["health_summary"] = m["health"].(map[string]any)["summary"]
	m["disclosure_channel"] = repo.DisclosureChannel
	m["disclosure_channel_at"] = repo.DisclosureChannelAt
	if repo.FederationOptedOut() {
		m["federation_opt_out"] = map[string]any{"at": repo.FederationOptOutAt, "reason": repo.FederationOptOutReason}
	} else {
		m["federation_opt_out"] = nil
	}
	global, _ := db.GetSetting(s.DB, db.SettingScanSchedule)
	m["scan_schedule"] = repo.ScanSchedule
	m["upstream_url"] = repo.UpstreamURL
	m["next_scheduled_scan_at"] = repo.NextScheduledScanAt
	m["global_scan_schedule"] = global
	m["has_threat_model_override"] = repo.ThreatModel != ""
	m["scan_config_set"] = strings.TrimSpace(repo.ScanConfig) != ""
	m["total_cost_usd"] = repoTotalCost(s.DB, repo.ID)
	m["unpriced_scan_count"] = repoUnpricedScans(s.DB, repo.ID)
	m["counts"] = counts
	m["latest_scan"] = s.uiRepoLatestScan(repo.ID, primary.DeepDive)
	m["compliance"] = uiRepoComplianceBadge(repo, counts)
	delete(counts, "compliance_passed")
	m["tm_commit"] = scanCommit(primary.ThreatModel)
	m["exports"] = map[string]any{
		"report_md": map[string]string{
			uiKeyURL:   fmt.Sprintf("/repositories/%d/report.md", repo.ID),
			"filename": repoReportFilename(&repo, false),
		},
		"report_upstream_md": map[string]string{
			uiKeyURL:   fmt.Sprintf("/repositories/%d/report.md?audience=upstream", repo.ID),
			"filename": repoReportFilename(&repo, true),
		},
	}
	m["is_local"] = repo.IsLocal()
	m["local_path"] = repo.LocalPath()
	return m, nil
}

// uiRepoHealthSummary is the tooltip text repoShow derives for the health
// badge.
func (s *Server) uiRepoHealthSummary(repo db.Repository) string {
	var packages []db.Package
	s.DB.Where("repository_id = ?", repo.ID).Find(&packages)
	evidenceComplete, err := db.RepositoryHealthEvidenceComplete(s.DB, repo.ID)
	if err != nil {
		s.Log.Error("repository health evidence", "repo", repo.ID, "err", err)
	}
	return db.AssessRepositoryHealth(repo, packages, s.repoMaintainers(repo.ID), evidenceComplete, time.Now()).Summary
}

// uiRepoComplianceBadge is the OpenSSF Baseline badge: level plus how many
// controls passed; nil when the repository has no compliance data.
func uiRepoComplianceBadge(repo db.Repository, counts map[string]int64) map[string]any {
	total := counts["compliance"]
	if total == 0 && repo.BaselineLevel == 0 {
		return nil
	}
	return map[string]any{
		"level":  fmt.Sprintf("L%d", repo.BaselineLevel),
		"passed": counts["compliance_passed"],
		"total":  total,
	}
}

// uiRepoCounts is every tab badge count, each one cheap COUNT rather than
// the loadRepoShowView list loads.
func (s *Server) uiRepoCounts(repo db.Repository, primary uiRepoPrimary) map[string]int64 {
	id := repo.ID
	active, paused := s.repoScanActionCounts(id)
	count := func(model any, where string, args ...any) int64 {
		var n int64
		s.DB.Model(model).Where(where, args...).Count(&n)
		return n
	}
	openFindings := func(filter string) int64 {
		return count(&db.Finding{}, "repository_id = ? AND status NOT IN ? AND "+filter, id, db.ClosedFindingLifecycles)
	}
	hiddenTypes := []string{db.DependencyDev, db.DependencyTest, db.DependencyBuild}
	var maintainers int64
	s.DB.Table("repository_maintainers").Where("repository_id = ?", id).Count(&maintainers)
	expected := s.uiRepoExpectedMatches(id)
	return map[string]int64{
		"active_scans":        active,
		"paused_scans":        paused,
		"failed_scans":        int64(countFailedScans(primary.Latest)),
		"new_findings":        repoNewFindingsCount(s.DB, id, ""),
		uiKeyFindings:         openFindings(nonScannerScanFilter),
		"scanner_findings":    openFindings(scannerScanFilter),
		uiKeyPackages:         count(&db.Package{}, "repository_id = ?", id),
		"alternatives":        count(&db.PackageAlternative{}, "repository_id = ?", id),
		"dependencies":        count(&db.Dependency{}, "repository_id = ? AND dependency_type NOT IN ?", id, hiddenTypes),
		"hidden_dependencies": count(&db.Dependency{}, "repository_id = ? AND dependency_type IN ?", id, hiddenTypes),
		uiKeyAdvisories:       count(&db.Advisory{}, "repository_id = ?", id),
		"dependents":          count(&db.Dependent{}, "repository_id = ?", id),
		"maintainers":         maintainers,
		"subprojects":         count(&db.Subproject{}, "repository_id = ?", id),
		"expected":            int64(len(expected.Expected)),
		"expected_matched":    int64(expected.MatchedTotal),
		"compliance":          count(&db.ComplianceControl{}, "repository_id = ?", id),
		"compliance_passed":   count(&db.ComplianceControl{}, "repository_id = ? AND status = ?", id, "PASS"),
		"conversations":       count(&db.Conversation{}, "repository_id = ? AND finding_id IS NULL", id),
	}
}

// uiLatestBenchmarkScanID is latestBenchmarkScan(gdb, repoID, "", "", "")
// without loading the scan's blobs.
func (s *Server) uiLatestBenchmarkScanID(repoID uint) uint {
	var ids []uint
	s.DB.Model(&db.Scan{}).Where("repository_id = ? AND status = ? AND skill_name IN ?",
		repoID, db.ScanDone, []string{deepDiveSkillName, vulnScanSkillName}).
		Order("id desc").Limit(1).Pluck("id", &ids)
	if len(ids) == 0 {
		return 0
	}
	return ids[0]
}

// uiRepoExpectedMatches is the Benchmark tab's matched/missed set.
func (s *Server) uiRepoExpectedMatches(repoID uint) expectedMatchSet {
	var expected []db.ExpectedFinding
	s.DB.Where("repository_id = ?", repoID).Order("file, cwe").Find(&expected)
	return expectedMatchesForRows(s.DB, repoID, s.uiLatestBenchmarkScanID(repoID), expected)
}

// uiRepoLatestScan is the latest deep-dive as a ScanRow plus its findings as
// FindingRows, each carrying the expected badge when the repo is benchmarked.
func (s *Server) uiRepoLatestScan(repoID uint, latest *db.Scan) map[string]any {
	if latest == nil {
		return nil
	}
	row, err := s.loadUIScanRow(latest.ID)
	if err != nil {
		return nil
	}
	var findings []db.Finding
	s.DB.Where("scan_id = ?", latest.ID).Order(severityOrder).Order("id desc").Find(&findings)
	row[uiKeyFindings] = s.uiRepoFindingRows(repoID, findings)
	return row
}

// uiRepoFindingRows projects findings as FindingRows and fills `expected`
// (matched|unexpected) when the repository has expected findings.
func (s *Server) uiRepoFindingRows(repoID uint, findings []db.Finding) []map[string]any {
	rows := s.uiFindingRows(findings)
	var expected []db.ExpectedFinding
	s.DB.Where("repository_id = ?", repoID).Find(&expected)
	if len(expected) == 0 {
		return rows
	}
	matched := expectedStatusForFindings(findings, expected)
	for i, f := range findings {
		if matched[f.ID] {
			rows[i]["expected"] = "matched"
		} else {
			rows[i]["expected"] = "unexpected"
		}
	}
	return rows
}

// ---------------------------------------------------------------- DELETE 409 body

// writeRepoDeleteInFlight writes the additive 409 body of
// DELETE /api/v1/repositories/{id}: the legacy `error` string plus
// code:"in_flight" and the active/paused counts, so a list-level delete can
// explain the refusal without loading RepoDetail.
func (s *Server) writeRepoDeleteInFlight(w http.ResponseWriter, repoID uint, err error) {
	active, paused := s.repoScanActionCounts(repoID)
	writeUIErrorExtra(w, http.StatusConflict, uiCodeInFlight, err.Error(), map[string]any{"active": active, "paused": paused})
}
