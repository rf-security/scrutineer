package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

// Repository enqueue actions (02 #45-#47). Each one is the JSON twin of an
// HTML form handler: same guards, same ScanOpts, a 202 with the queued ids
// instead of a redirect. These are only ever exercised with newTestServer.

// uiRepoModelBody is the common {model} body.
type uiRepoModelBody struct {
	Model string `json:"model"`
}

// activeSkillByName loads an installed, active skill.
func (s *Server) activeSkillByName(name string) (db.Skill, error) {
	var skill db.Skill
	err := s.DB.Where("name = ? AND active = ?", name, true).First(&skill).Error
	return skill, err
}

// ---------------------------------------------------------------- #45 scan

func (s *Server) uiRepoScanAction(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	var body struct {
		Model      string `json:"model"`
		SubPath    string `json:"sub_path"`
		RescanMode string `json:"rescan_mode"`
	}
	if !uiDecodeBody(w, r, &body) {
		return
	}
	mode := strings.TrimSpace(body.RescanMode)
	subPath := strings.TrimSpace(body.SubPath)
	switch mode {
	case "", db.ScanRescanModeFull:
	case db.ScanRescanModeDiff:
		ids, err := s.enqueueDiffRescanGroupIDs(r.Context(), repo.ID, body.Model, subPath)
		if err != nil {
			mapEnqueueErr(w, err)
			return
		}
		enqueueBatchResult(w, enqueueBatch{ScanIDs: ids, Queued: len(ids), Message: fmt.Sprintf("Diff rescan queued %d scan(s)", len(ids))})
		return
	default:
		writeUIFields(w, uiFieldErrors{"rescan_mode": "must be \"\", full or diff"})
		return
	}
	skill, err := s.activeSkillByName(deepDiveSkillName)
	if err != nil {
		mapEnqueueErr(w, errDeepDiveMissing)
		return
	}
	scanID, err := s.enqueueSkillWith(r.Context(), repo.ID, skill.ID, ScanOpts{
		Model:      body.Model,
		SubPath:    subPath,
		RescanMode: mode,
		ScanGroup:  uuid.NewString(),
	})
	if err != nil {
		mapEnqueueErr(w, err)
		return
	}
	enqueueResult(w, scanID)
}

// enqueueDiffRescanGroupIDs is enqueueDiffRescanGroup returning the queued
// scan ids (server.go's version returns only the count and is shared with the
// scheduler). TODO(WP-API-3): have enqueueDiffRescanGroup delegate here once
// server.go extractions are merged.
func (s *Server) enqueueDiffRescanGroupIDs(ctx context.Context, repoID uint, model, subPath string) ([]uint, error) {
	if _, err := s.activeSkillByName(deepDiveSkillName); err != nil {
		return nil, errDeepDiveMissing
	}
	group := uuid.NewString()
	ids := []uint{}
	for _, name := range []string{reconSkillName, historySkillName, "embedded-native", threatModelSkillName, "semgrep", "betterleaks"} {
		skill, err := s.activeSkillByName(name)
		if err != nil {
			continue
		}
		id, err := s.enqueueSkillWith(ctx, repoID, skill.ID, ScanOpts{
			Model:      model,
			SubPath:    subPath,
			RescanMode: db.ScanRescanModeDiff,
			ScanGroup:  group,
		})
		if err != nil {
			return ids, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// ---------------------------------------------------------------- #46 scan-all, verify-all, threat-model-run, run-skill

func (s *Server) uiRepoScanAllAction(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	var body uiRepoModelBody
	if !uiDecodeBody(w, r, &body) {
		return
	}
	skill, err := s.activeSkillByName(deepDiveSkillName)
	if err != nil {
		mapEnqueueErr(w, errDeepDiveMissing)
		return
	}
	var subprojects []db.Subproject
	s.DB.Where("repository_id = ?", repo.ID).Order("path").Find(&subprojects)
	// As repoScanAll: one group across the fan-out, skipping subprojects
	// with a queued or running root deep-dive.
	group := uuid.NewString()
	res := enqueueBatch{}
	for _, sub := range subprojects {
		subPath := sub.ScanSubPath()
		var inflight int64
		s.DB.Model(&db.Scan{}).
			Where("repository_id = ? AND sub_path = ? AND skill_id = ? AND status IN ?",
				repo.ID, subPath, skill.ID, []db.ScanStatus{db.ScanQueued, db.ScanRunning}).
			Where("COALESCE(focus_area, '') = '' AND COALESCE(exploration_mode, '') = ''").
			Count(&inflight)
		if inflight > 0 {
			res.Skipped++
			continue
		}
		id, err := s.enqueueSkillWith(r.Context(), repo.ID, skill.ID, ScanOpts{Model: body.Model, SubPath: subPath, ScanGroup: group})
		if err != nil {
			res.Errored++
			continue
		}
		res.ScanIDs = append(res.ScanIDs, id)
		res.Queued++
	}
	res.Message = scanAllToast(res.Queued, res.Skipped, res.Errored).Title
	enqueueBatchResult(w, res)
}

func (s *Server) uiRepoVerifyAllAction(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	var body uiRepoModelBody
	if !uiDecodeBody(w, r, &body) {
		return
	}
	category := r.URL.Query().Get("category")
	if category != "" && category != UncategorizedCWE && !slices.Contains(CWECategories(), category) {
		uiBadParam(w, fmt.Sprintf("invalid category %q", category))
		return
	}
	skill, err := s.activeSkillByName(verifySkillName)
	if err != nil {
		writeUIError(w, http.StatusPreconditionFailed, uiCodePreconditionFailed, verifySkillName+" skill is not installed", nil)
		return
	}
	q := s.DB.Model(&db.Finding{}).
		Where("repository_id = ? AND status = ? AND scan_id IN (?)", repo.ID, db.FindingNew, findingsScanIDs(s.DB))
	if category != "" {
		q = applyCWECategoryFilter(q, category)
	}
	var findings []db.Finding
	q.Select("id").Find(&findings)
	res := enqueueBatch{}
	for _, f := range findings {
		var inflight int64
		s.DB.Model(&db.Scan{}).
			Where("finding_id = ? AND skill_id = ? AND status IN ?", f.ID, skill.ID, []db.ScanStatus{db.ScanQueued, db.ScanRunning}).
			Count(&inflight)
		if inflight > 0 {
			res.Skipped++
			continue
		}
		id, err := s.enqueueSkillScoped(r.Context(), repo.ID, skill.ID, new(f.ID), body.Model)
		if err != nil {
			res.Errored++
			continue
		}
		res.ScanIDs = append(res.ScanIDs, id)
		res.Queued++
	}
	res.Message = verifyAllToast(res.Queued, res.Skipped, res.Errored).Title
	enqueueBatchResult(w, res)
}

func (s *Server) uiRepoThreatModelRunAction(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	var body struct {
		ThreatModel *string `json:"threat_model"`
	}
	if !uiDecodeBody(w, r, &body) {
		return
	}
	if body.ThreatModel != nil {
		model, err := normaliseThreatModel(*body.ThreatModel)
		if err != nil {
			writeUIFields(w, uiFieldErrors{"threat_model": "threat model is not valid JSON: " + err.Error()})
			return
		}
		if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).Update("threat_model", model).Error; err != nil {
			uiInternal(w, err)
			return
		}
		s.publishRepository(repo.ID, uiChangeUpdated)
	}
	skill, err := s.activeSkillByName(deepDiveSkillName)
	if err != nil {
		mapEnqueueErr(w, errDeepDiveMissing)
		return
	}
	scanID, err := s.enqueueSkillWith(r.Context(), repo.ID, skill.ID, ScanOpts{})
	if err != nil {
		mapEnqueueErr(w, err)
		return
	}
	enqueueResult(w, scanID)
}

func (s *Server) uiRepoRunSkillAction(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	var body struct {
		SkillID      uint    `json:"skill_id"`
		Model        string  `json:"model"`
		EgressPolicy string  `json:"egress_policy"`
		MaxCostUSD   float64 `json:"max_cost_usd"`
	}
	if !uiDecodeBody(w, r, &body) {
		return
	}
	if body.SkillID == 0 {
		writeUIFields(w, uiFieldErrors{"skill_id": "required"})
		return
	}
	var skill db.Skill
	if err := s.DB.First(&skill, body.SkillID).Error; err != nil || !skill.Active {
		uiNotFound(w, "active skill")
		return
	}
	if err := validateMaxCostUSD(body.MaxCostUSD); err != nil {
		writeUIFields(w, uiFieldErrors{"max_cost_usd": err.Error()})
		return
	}
	scanID, err := s.enqueueSkillWith(r.Context(), repo.ID, skill.ID, ScanOpts{
		Model:        body.Model,
		EgressPolicy: strings.TrimSpace(body.EgressPolicy),
		MaxCostUSD:   body.MaxCostUSD,
	})
	if err != nil {
		mapEnqueueErr(w, err)
		return
	}
	enqueueResult(w, scanID)
}

// ---------------------------------------------------------------- #47 validate-fix

// uiValidateFixBody is the ValidateFixRequest.
type uiValidateFixBody struct {
	Ref        string `json:"ref"`
	Model      string `json:"model"`
	FindingIDs []uint `json:"finding_ids"`
}

// errValidateFix is a rejected validate-fix request (422 field error).
type errValidateFix struct{ field, msg string }

func (e errValidateFix) Error() string { return e.msg }

// validateFixPlan resolves and checks a validate-fix request with the rules
// of validateFix: a valid ref, findings on this repository sharing one
// baseline scan that has a skill to re-run.
func (s *Server) validateFixPlan(repoID uint, body uiValidateFixBody) ([]db.Finding, db.Scan, error) {
	ref := strings.TrimSpace(body.Ref)
	if ref == "" {
		return nil, db.Scan{}, errValidateFix{"ref", "a fix ref is required"}
	}
	if err := worker.ValidateGitRef(ref); err != nil {
		return nil, db.Scan{}, errValidateFix{"ref", fmt.Sprintf("invalid fix ref: %v", err)}
	}
	ids := uniqueIDs(body.FindingIDs)
	if len(ids) == 0 {
		return nil, db.Scan{}, errValidateFix{"finding_ids", "at least one finding id is required"}
	}
	var findings []db.Finding
	if err := s.DB.Where("id IN ? AND repository_id = ?", ids, repoID).Find(&findings).Error; err != nil {
		return nil, db.Scan{}, err
	}
	if len(findings) != len(ids) {
		return nil, db.Scan{}, errValidateFix{"finding_ids", "some findings were not found on this repository"}
	}
	baselineID := findings[0].ScanID
	for _, f := range findings {
		if f.ScanID != baselineID {
			return nil, db.Scan{}, errValidateFix{"finding_ids", "all findings must come from the same baseline scan"}
		}
	}
	var baseline db.Scan
	if err := s.DB.Omit(uiScanOmit...).First(&baseline, baselineID).Error; err != nil {
		return nil, db.Scan{}, err
	}
	if baseline.SkillID == nil {
		return nil, db.Scan{}, errValidateFix{"finding_ids", "baseline scan has no skill to re-run against the fix ref"}
	}
	return findings, baseline, nil
}

func uniqueIDs(ids []uint) []uint {
	seen := map[uint]bool{}
	out := make([]uint, 0, len(ids))
	for _, id := range ids {
		if id != 0 && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// uiRepoValidateFixAction is the JSON twin of validateFix (repo-scoped).
// TODO(WP-API-3): switch to WP-API-2's shared enqueueValidateFix helper once
// both packages are merged; until then the guards are duplicated here.
func (s *Server) uiRepoValidateFixAction(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	var body uiValidateFixBody
	if !uiDecodeBody(w, r, &body) {
		return
	}
	findings, baseline, err := s.validateFixPlan(repo.ID, body)
	var vErr errValidateFix
	switch {
	case errors.As(err, &vErr):
		writeUIFields(w, uiFieldErrors{vErr.field: vErr.msg})
		return
	case err != nil:
		uiInternal(w, err)
		return
	}
	ref := strings.TrimSpace(body.Ref)
	s.enqueueValidateFixVerify(r, repo.ID, findings, ref, body.Model)
	baselineID := baseline.ID
	anchorID, err := s.enqueueSkillWith(r.Context(), repo.ID, *baseline.SkillID, ScanOpts{
		Model:          body.Model,
		Ref:            ref,
		SubPath:        baseline.SubPath,
		ScopeMode:      baseline.ScopeMode,
		BaselineScanID: &baselineID,
	})
	if err != nil {
		mapEnqueueErr(w, err)
		return
	}
	ids := make([]uint, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
	}
	var verifyIDs []uint
	s.DB.Model(&db.Scan{}).
		Where("finding_id IN ? AND skill_name = ? AND ref = ? AND status IN ?", ids, verifySkillName, ref, inFlightScanStatuses()).
		Order("id").Pluck("id", &verifyIDs)
	if verifyIDs == nil {
		verifyIDs = []uint{}
	}
	writeUIJSON(w, http.StatusAccepted, map[string]any{uiEventScanIDKey: anchorID, "verify_scan_ids": verifyIDs})
}
