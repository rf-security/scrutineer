package web

import (
	"net/http"
	"slices"
	"strings"

	"scrutineer/internal/db"
)

// Finding sub-resource reads (#13-#16). Every projection is snake_case; db
// rows are never serialised directly.

const uiHistoryDefaultPageSize = 100

// ---------------------------------------------------------------- projections

func uiFindingNote(n db.FindingNote) map[string]any {
	return map[string]any{"id": n.ID, "body": n.Body, "by": n.By, uiKeyCreatedAt: n.CreatedAt}
}

func uiFindingCommunication(c db.FindingCommunication) map[string]any {
	return map[string]any{
		"id": c.ID, "channel": c.Channel, "direction": c.Direction, "actor": c.Actor, "body": c.Body,
		"offered_help": c.OfferedHelp, "at": c.At, uiKeyCreatedAt: c.CreatedAt,
	}
}

func uiFindingReference(ref db.FindingReference) map[string]any {
	return map[string]any{"id": ref.ID, uiKeyURL: ref.URL, "tags": ref.Tags, "summary": ref.Summary, uiKeyCreatedAt: ref.CreatedAt}
}

// uiFindingReview projects a review; agreed is null when there is no
// automated outcome to agree with.
func uiFindingReview(rv db.FindingReview) map[string]any {
	var agreed any
	if rv.AutomatedOutcome != "" {
		agreed = rv.AutomatedOutcome == rv.Verdict
	}
	return map[string]any{
		"id": rv.ID, "verdict": rv.Verdict, "reason": rv.Reason, "reviewer": rv.Reviewer,
		"automated_outcome": rv.AutomatedOutcome, "agreed": agreed, uiKeyCreatedAt: rv.CreatedAt,
	}
}

func uiFindingHistoryRow(h db.FindingHistory) map[string]any {
	return map[string]any{
		"id": h.ID, "field": h.Field, "old_value": h.OldValue, "new_value": h.NewValue,
		"source": string(h.Source), "by": h.By, uiKeyCreatedAt: h.CreatedAt,
	}
}

// uiDisclosureSubmission omits the request/response payloads: an Akrites
// receipt grants access to intake status (see db.DisclosureSubmission).
func uiDisclosureSubmission(d db.DisclosureSubmission) map[string]any {
	return map[string]any{
		"id": d.ID, "channel": d.Channel, "endpoint": d.Endpoint, "external_id": d.ExternalID, uiKeyURL: d.URL,
		statusKey: d.Status, "status_at": d.StatusAt, "last_error": d.LastError, "actor": d.Actor,
		uiKeyCreatedAt: d.CreatedAt, uiKeyUpdatedAt: d.UpdatedAt,
	}
}

func uiLabels(labels []db.FindingLabel) []map[string]any {
	out := make([]map[string]any, len(labels))
	for i, l := range labels {
		out[i] = uiLabel(l)
	}
	return out
}

// sortedLabels orders labels by name (Preload order is unspecified).
func sortedLabels(labels []db.FindingLabel) []db.FindingLabel {
	out := slices.Clone(labels)
	slices.SortFunc(out, func(a, b db.FindingLabel) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// projectAll maps rows through project, never returning nil.
func projectAll[T any](rows []T, project func(T) map[string]any) []map[string]any {
	out := make([]map[string]any, len(rows))
	for i, row := range rows {
		out[i] = project(row)
	}
	return out
}

// ---------------------------------------------------------------- simple lists (#13, #14)

func (s *Server) uiFindingHistory(w http.ResponseWriter, r *http.Request) {
	page, err := parseListPageDefault(r, uiHistoryDefaultPageSize)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	id, ok := s.uiFindingExists(w, r)
	if !ok {
		return
	}
	q := s.DB.Model(&db.FindingHistory{}).Where("finding_id = ?", id)
	var total int64
	if err := q.Count(&total).Error; err != nil {
		uiInternal(w, err)
		return
	}
	var rows []db.FindingHistory
	if err := q.Order("created_at desc, id desc").Limit(page.PageSize).Offset(page.offset()).Find(&rows).Error; err != nil {
		uiInternal(w, err)
		return
	}
	writeList(w, projectAll(rows, uiFindingHistoryRow), total, page)
}

// uiFindingChildList serves one finding-owned table as an array.
func uiFindingChildList[T any](s *Server, order string, project func(T) map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.uiFindingExists(w, r)
		if !ok {
			return
		}
		var rows []T
		if err := s.DB.Where("finding_id = ?", id).Order(order).Find(&rows).Error; err != nil {
			uiInternal(w, err)
			return
		}
		writeUIJSON(w, http.StatusOK, projectAll(rows, project))
	}
}

func (s *Server) uiFindingNotes(w http.ResponseWriter, r *http.Request) {
	uiFindingChildList(s, "created_at desc, id desc", uiFindingNote)(w, r)
}

func (s *Server) uiFindingCommunications(w http.ResponseWriter, r *http.Request) {
	uiFindingChildList(s, "at desc, id desc", uiFindingCommunication)(w, r)
}

func (s *Server) uiFindingReferences(w http.ResponseWriter, r *http.Request) {
	uiFindingChildList(s, "id desc", uiFindingReference)(w, r)
}

func (s *Server) uiFindingReviews(w http.ResponseWriter, r *http.Request) {
	uiFindingChildList(s, "created_at desc, id desc", uiFindingReview)(w, r)
}

func (s *Server) uiFindingSubmissions(w http.ResponseWriter, r *http.Request) {
	uiFindingChildList(s, "id desc", uiDisclosureSubmission)(w, r)
}

func (s *Server) uiFindingLabels(w http.ResponseWriter, r *http.Request) {
	f, ok := s.loadUIFinding(w, r)
	if !ok {
		return
	}
	writeUIJSON(w, http.StatusOK, uiLabels(sortedLabels(f.Labels)))
}

// ---------------------------------------------------------------- views (#15)

// uiVerificationView projects loadFindingVerificationViews' struct.
func uiVerificationView(v findingVerificationView) map[string]any {
	m := findingVerificationResponse(&v.FindingVerification)
	m["score_label"] = v.ScoreLabel
	m["verification_feedback"] = v.VerificationFeedback
	m["has_rubric"] = v.HasRubric
	criteria := make([]map[string]any, len(v.Criteria))
	for i, c := range v.Criteria {
		criteria[i] = map[string]any{uiKeyName: c.Name, "criterion": c.Criterion}
	}
	m["criteria"] = criteria
	m["attempts"] = v.Attempts
	if v.Attempts == nil {
		m["attempts"] = []any{}
	}
	m["attack_tree"] = v.AttackTree
	m["control_bypass"] = v.ControlBypass
	prereqs := make([]map[string]any, len(v.Prerequisites))
	for i, p := range v.Prerequisites {
		prereqs[i] = map[string]any{uiKeyName: p.Name, "assessment": p.Assessment}
	}
	m["prerequisites"] = prereqs
	return m
}

func (s *Server) uiFindingVerifications(w http.ResponseWriter, r *http.Request) {
	id, ok := s.uiFindingExists(w, r)
	if !ok {
		return
	}
	views, err := loadFindingVerificationViews(s.DB.WithContext(r.Context()), id)
	if err != nil {
		uiInternal(w, err)
		return
	}
	writeUIJSON(w, http.StatusOK, projectAll(views, uiVerificationView))
}

// uiAttackPathView projects loadFindingAttackPathViews' struct.
func uiAttackPathView(v findingAttackPathView) map[string]any {
	m := findingAttackPathResponse(&v.FindingAttackPath)
	m["parsed"] = v.Parsed
	if v.Parsed {
		m["assessment"] = v.Assessment
	} else {
		m["assessment"] = nil
	}
	return m
}

func (s *Server) uiFindingAttackPaths(w http.ResponseWriter, r *http.Request) {
	id, ok := s.uiFindingExists(w, r)
	if !ok {
		return
	}
	views, err := loadFindingAttackPathViews(s.DB.WithContext(r.Context()), id)
	if err != nil {
		uiInternal(w, err)
		return
	}
	writeUIJSON(w, http.StatusOK, projectAll(views, uiAttackPathView))
}

// uiObservationJSON is findingObservationResponse plus the ordered evidence
// fields the finding page renders.
type uiObservationJSON struct {
	findingObservationJSON
	EvidenceFields []map[string]string `json:"evidence_fields"`
}

func uiObservationRow(o db.FindingObservation) uiObservationJSON {
	out := uiObservationJSON{findingObservationJSON: findingObservationResponse(&o), EvidenceFields: []map[string]string{}}
	if m, ok := out.Evidence.(map[string]any); ok {
		for _, k := range observationEvidenceOrder {
			if v, ok := m[k].(string); ok && v != "" {
				out.EvidenceFields = append(out.EvidenceFields, map[string]string{uiKeyName: k, "value": v})
			}
		}
	}
	return out
}

// uiFindingObservations pages every observation of the finding and of the
// findings merged into it (newest first). disagreements compares all of
// them, not just the page, as the finding page does.
func (s *Server) uiFindingObservations(w http.ResponseWriter, r *http.Request) {
	page, err := parseListPage(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	id, ok := s.uiFindingExists(w, r)
	if !ok {
		return
	}
	gdb := s.DB.WithContext(r.Context())
	ids, err := db.ContributionFindingIDs(gdb, id)
	if err != nil {
		uiInternal(w, err)
		return
	}
	q := gdb.Model(&db.FindingObservation{}).Where("finding_id IN ?", ids)
	var total int64
	if err := q.Count(&total).Error; err != nil {
		uiInternal(w, err)
		return
	}
	var rows []db.FindingObservation
	if err := q.Order("created_at desc, id desc").Limit(page.PageSize).Offset(page.offset()).Find(&rows).Error; err != nil {
		uiInternal(w, err)
		return
	}
	var compared []db.FindingObservation
	if err := gdb.Model(&db.FindingObservation{}).Select(uiFacetSeverity, "reachability", "rating").
		Where("finding_id IN ?", ids).Find(&compared).Error; err != nil {
		uiInternal(w, err)
		return
	}
	disagreements := nonNilStrings(observationDisagreements(compared))
	items := make([]uiObservationJSON, len(rows))
	for i, row := range rows {
		items[i] = uiObservationRow(row)
	}
	writeListWith(w, items, total, page, map[string]any{
		"disagreement": len(disagreements) > 0, "disagreements": disagreements,
	})
}

// uiRemediationAttempt projects one loadRemediationAttemptViews row.
func uiRemediationAttempt(v remediationAttemptView) map[string]any {
	return remediationAttemptResponse(&v.RemediationAttempt, v.Validation)
}

func (s *Server) uiFindingRemediation(w http.ResponseWriter, r *http.Request) {
	id, ok := s.uiFindingExists(w, r)
	if !ok {
		return
	}
	views, err := loadRemediationAttemptViews(s.DB.WithContext(r.Context()), id)
	if err != nil {
		uiInternal(w, err)
		return
	}
	attempts := projectAll(views, uiRemediationAttempt)
	var current, attemptID *uint
	var currentRow any
	if len(views) > 0 {
		current = &views[0].ID
		attemptID = current
		currentRow = attempts[0]
	}
	reattack, reattackOK := s.openFindingSkillScanForAttempt(id, reattackSkillName, attemptID)
	writeUIJSON(w, http.StatusOK, map[string]any{
		"attempts": attempts, "current": currentRow,
		"reattack_in_flight": uiScanRef(reattack, reattackOK), "patch": s.uiPatchView(id),
	})
}

// uiDependent projects a db.Dependent.
func uiDependent(d db.Dependent) map[string]any {
	return map[string]any{
		"id": d.ID, uiKeyName: d.Name, uiKeyEcosystem: d.Ecosystem, uiKeyPURL: d.PURL, "repository_url": d.RepositoryURL,
		"downloads": d.Downloads, "dependent_repos": d.DependentRepos, "registry_url": d.RegistryURL,
		"latest_version": d.LatestVersion,
	}
}

// uiFindingExposureRows loads the finding/dependent rows and their dependents.
func (s *Server) uiFindingExposureRows(findingID uint) ([]db.FindingDependent, map[uint]db.Dependent, error) {
	var fdRows []db.FindingDependent
	if err := s.DB.Where("finding_id = ?", findingID).Find(&fdRows).Error; err != nil {
		return nil, nil, err
	}
	deps := map[uint]db.Dependent{}
	if len(fdRows) == 0 {
		return fdRows, deps, nil
	}
	ids := make([]uint, len(fdRows))
	for i, row := range fdRows {
		ids[i] = row.DependentID
	}
	var depRows []db.Dependent
	if err := s.DB.Where("id IN ?", ids).Find(&depRows).Error; err != nil {
		return nil, nil, err
	}
	for _, d := range depRows {
		deps[d.ID] = d
	}
	return fdRows, deps, nil
}

func (s *Server) uiFindingExposures(w http.ResponseWriter, r *http.Request) {
	f, ok := s.loadUIFinding(w, r)
	if !ok {
		return
	}
	var scan db.Scan
	s.DB.Omit(uiScanOmit...).First(&scan, f.ScanID)
	hasDependents, err := repoHasDependents(s.DB, scan.RepositoryID)
	if err != nil {
		uiInternal(w, err)
		return
	}
	fdRows, deps, err := s.uiFindingExposureRows(f.ID)
	if err != nil {
		uiInternal(w, err)
		return
	}
	rows := make([]map[string]any, 0, len(fdRows))
	for _, row := range fdRows {
		rows = append(rows, map[string]any{
			"dependent": uiDependent(deps[row.DependentID]), statusKey: row.Status,
			"justification": row.Justification, "why": row.Rationale, "at": row.UpdatedAt,
		})
	}
	writeUIJSON(w, http.StatusOK, map[string]any{
		"show": findingSupportsExposure(scan) && hasDependents, "has_dependents": hasDependents, "rows": rows,
	})
}

// ---------------------------------------------------------------- migration guide (#16)

func uiMigrationDependent(row migrationDependentRow) map[string]any {
	return map[string]any{
		"dependent_id": row.DependentID, uiKeyName: row.Name, uiKeyEcosystem: row.Ecosystem,
		"repository_url": row.RepositoryURL, "dependent_repos": row.DependentRepos, statusKey: row.Status,
		"rationale": row.Rationale, uiKeyUpdatedAt: row.UpdatedAt, "campaign_status": string(row.CampaignStatus),
		"campaign_note": row.CampaignNote, "campaign_updated_at": row.CampaignUpdatedAt,
	}
}

func uiMigrationPackage(p db.Package) map[string]any {
	return map[string]any{
		"id": p.ID, uiKeyName: p.Name, uiKeyEcosystem: p.Ecosystem, uiKeyPURL: p.PURL, "licenses": p.Licenses,
		"latest_version": p.LatestVersion, "downloads": p.Downloads, "dependent_packages": p.DependentPackages,
		"dependent_repos": p.DependentRepos, "registry_url": p.RegistryURL, "latest_release_at": p.LatestReleaseAt,
		"risk_flags": p.RiskFlags,
	}
}

// uiMigrationGuide projects loadFindingMigrationGuide; available is false
// (and the lists empty) when the repository does not warrant a guide.
func uiMigrationGuide(g *findingMigrationGuide) map[string]any {
	out := map[string]any{
		"available": g != nil, "health": "", uiKeyPackages: []map[string]any{}, "alternatives": []packageAlternativeResponse{},
		"campaign_statuses": []string{}, "priority_dependents": []map[string]any{},
		"known_safe_count": 0, "fixed_count": 0, "total_exposure_rows": 0,
	}
	if g == nil {
		return out
	}
	statuses := make([]string, len(g.CampaignStatuses))
	for i, st := range g.CampaignStatuses {
		statuses[i] = string(st)
	}
	out["health"] = string(g.Health)
	out[uiKeyPackages] = projectAll(g.Packages, uiMigrationPackage)
	out["alternatives"] = packageAlternativeResponses(g.Alternatives)
	out["campaign_statuses"] = statuses
	out["priority_dependents"] = projectAll(g.PriorityDependents, uiMigrationDependent)
	out["known_safe_count"] = g.KnownSafeCount
	out["fixed_count"] = g.FixedCount
	out["total_exposure_rows"] = g.TotalExposureRows
	return out
}

func (s *Server) uiFindingMigrationGuide(w http.ResponseWriter, r *http.Request) {
	f, ok := s.loadUIFinding(w, r)
	if !ok {
		return
	}
	var repo db.Repository
	if err := s.DB.First(&repo, f.RepositoryID).Error; err != nil {
		uiDBError(w, err, uiKeyRepository)
		return
	}
	fdRows, deps, err := s.uiFindingExposureRows(f.ID)
	if err != nil {
		uiInternal(w, err)
		return
	}
	guide, err := loadFindingMigrationGuide(s.DB.WithContext(r.Context()), repo, fdRows, deps)
	if err != nil {
		uiInternal(w, err)
		return
	}
	writeUIJSON(w, http.StatusOK, uiMigrationGuide(guide))
}
