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

// uiRepoValidateFixAction is the JSON twin of validateFix (repo-scoped). The
// request body is the ValidateFixRequest (uiValidateFixBody, shared with the
// finding-scoped #21); the guards and enqueues live in enqueueValidateFix.
func (s *Server) uiRepoValidateFixAction(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	var body uiValidateFixBody
	if !uiDecodeBody(w, r, &body) {
		return
	}
	res, err := s.enqueueValidateFix(r.Context(), repo.ID, strings.TrimSpace(body.Ref), uniqueIDs(body.FindingIDs), body.Model)
	var input validateFixInputError
	switch {
	case errors.As(err, &input):
		writeUIFields(w, uiFieldErrors{input.Field: input.Msg})
		return
	case err != nil:
		mapEnqueueErr(w, err)
		return
	}
	writeUIJSON(w, http.StatusAccepted, map[string]any{uiEventScanIDKey: res.AnchorID, "verify_scan_ids": res.VerifyScanIDs})
}
