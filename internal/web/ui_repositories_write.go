package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/repoconfig"
)

// Repository writes of the /api/v1/ui surface (02 #39-#42, #44): the RepoDetail
// autosave PATCH and the tab sub-resources. Every write publishes a
// `repository` event so open views refetch.

// uiDecodeBody decodes an optional JSON body (1 MiB cap) into dst. An empty
// body leaves dst untouched; malformed JSON is a 400 envelope.
func uiDecodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	return uiDecodeBodyLimit(w, r, dst, apiMaxBody)
}

func uiDecodeBodyLimit(w http.ResponseWriter, r *http.Request, dst any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil && !errors.Is(err, io.EOF) {
		uiBadParam(w, "invalid JSON request body: "+err.Error())
		return false
	}
	return true
}

// preferRepresentation reports Prefer: return=representation.
func preferRepresentation(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Prefer"), "return=representation")
}

// ---------------------------------------------------------------- #39 PATCH

// uiRepoPatchBody is the partial RepoPatch; nil fields are left alone.
type uiRepoPatchBody struct {
	DisclosureChannel *string `json:"disclosure_channel"`
	FederationOptOut  *struct {
		Enabled bool   `json:"enabled"`
		Reason  string `json:"reason"`
	} `json:"federation_opt_out"`
	ScanSchedule *string `json:"scan_schedule"`
	UpstreamURL  *string `json:"upstream_url"`
	ThreatModel  *string `json:"threat_model"`
	ScanConfig   *string `json:"scan_config"`
}

// uiRepoPatchPlan is a validated PATCH: normalised values ready to write.
type uiRepoPatchPlan struct {
	columns map[string]any
	fields  map[string]any
}

// validate checks every supplied field with the HTML handlers' rules and
// returns the normalised column writes, or a uiFieldErrors naming each bad
// field.
func (b uiRepoPatchBody) validate() (uiRepoPatchPlan, error) {
	plan := uiRepoPatchPlan{columns: map[string]any{}, fields: map[string]any{}}
	errs := uiFieldErrors{}
	if b.ScanSchedule != nil {
		schedule := strings.TrimSpace(*b.ScanSchedule)
		if schedule != "" && schedule != ScheduleOff {
			if _, err := ScheduleNext(schedule, time.Now()); err != nil {
				errs["scan_schedule"] = "invalid schedule: " + err.Error()
			}
		}
		plan.columns["scan_schedule"] = schedule
		plan.fields["scan_schedule"] = schedule
	}
	if b.UpstreamURL != nil {
		upstream, err := normaliseUpstreamURL(*b.UpstreamURL)
		if err != nil {
			errs["upstream_url"] = err.Error()
		}
		plan.columns["upstream_url"] = upstream
		plan.fields["upstream_url"] = upstream
	}
	if b.ScanSchedule != nil || b.UpstreamURL != nil {
		// As repoScheduleUpdate: the next scheduler tick recomputes it.
		plan.columns["next_scheduled_scan_at"] = nil
	}
	if b.ThreatModel != nil {
		model, err := normaliseThreatModel(*b.ThreatModel)
		if err != nil {
			errs["threat_model"] = "threat model is not valid JSON: " + err.Error()
		}
		plan.columns["threat_model"] = model
		plan.fields["threat_model"] = model
	}
	if b.ScanConfig != nil {
		config, _, err := repoconfig.Normalise(*b.ScanConfig)
		if err != nil {
			errs["scan_config"] = "scan config is not valid YAML: " + err.Error()
		}
		plan.columns["scan_config"] = config
		plan.fields["scan_config"] = config
	}
	if len(errs) > 0 {
		return plan, errs
	}
	return plan, nil
}

// normaliseUpstreamURL applies repoScheduleUpdate's upstream rules: empty
// clears, otherwise an https repository URL normalised to its clone URL.
func normaliseUpstreamURL(raw string) (string, error) {
	upstream := strings.TrimSpace(raw)
	if upstream == "" {
		return "", nil
	}
	if !strings.HasPrefix(upstream, "https://") {
		return "", errors.New("upstream URL must start with https://")
	}
	input, err := ParseRepoInput(upstream)
	if err != nil {
		return "", errors.New(strings.Replace(err.Error(), "repository URL", "upstream URL", 1))
	}
	return input.CloneURL, nil
}

func (s *Server) uiRepoPatch(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r, "disclosure_channel", "federation_opt_out_reason")
	if !ok {
		return
	}
	var body uiRepoPatchBody
	if !uiDecodeBody(w, r, &body) {
		return
	}
	plan, err := body.validate()
	if err != nil {
		writeUIFields(w, err)
		return
	}
	current, err := s.loadUIRepoRow(repo.ID)
	if err != nil {
		uiInternal(w, err)
		return
	}
	if !checkIfMatch(w, r, repo.UpdatedAt, current) {
		return
	}
	if err := s.applyRepoPatch(repo, body, plan); err != nil {
		uiInternal(w, err)
		return
	}
	s.publishRepository(repo.ID, uiChangeUpdated)
	s.writeRepoPatchResponse(w, r, repo.ID, plan.fields)
}

// applyRepoPatch writes a validated PATCH. Disclosure channel and federation
// opt-out go through their dedicated helpers (route-record stamping, the
// federation lock and scan sweep); the plain columns are one UPDATE. The row
// version is bumped once at the end so every PATCH yields a new ETag.
func (s *Server) applyRepoPatch(repo db.Repository, body uiRepoPatchBody, plan uiRepoPatchPlan) error {
	if body.DisclosureChannel != nil {
		if err := db.SetDisclosureChannel(s.DB, repo.ID, *body.DisclosureChannel, db.SourceAnalyst, ""); err != nil {
			return err
		}
		plan.fields["disclosure_channel"] = strings.TrimSpace(*body.DisclosureChannel)
	}
	if fo := body.FederationOptOut; fo != nil {
		if err := s.setFederationOptOut(repo, fo.Enabled, fo.Reason); err != nil {
			return err
		}
		plan.fields["federation_opt_out"] = map[string]any{"enabled": fo.Enabled, "reason": strings.TrimSpace(fo.Reason)}
	}
	plan.columns["updated_at"] = time.Now()
	return s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).Updates(plan.columns).Error
}

// writeRepoPatchResponse writes the slim PATCH response (RepoRow + fields +
// ETag), or RepoDetail under Prefer: return=representation.
func (s *Server) writeRepoPatchResponse(w http.ResponseWriter, r *http.Request, repoID uint, fields map[string]any) {
	var repo db.Repository
	cols := append(append([]string{}, uiRepoListColumns...), "disclosure_channel", "disclosure_channel_at",
		"federation_opt_out_reason", "threat_model", "scan_config", "baseline_level")
	if err := s.DB.Select(cols).First(&repo, repoID).Error; err != nil {
		uiDBError(w, err, "repository")
		return
	}
	setETag(w, repo.UpdatedAt)
	if preferRepresentation(r) {
		detail, err := s.uiRepoDetailView(repo)
		if err != nil {
			uiInternal(w, err)
			return
		}
		writeUIJSON(w, http.StatusOK, detail)
		return
	}
	row, err := s.loadUIRepoRow(repoID)
	if err != nil {
		uiInternal(w, err)
		return
	}
	row["fields"] = fields
	writeUIJSON(w, http.StatusOK, row)
}

// ---------------------------------------------------------------- #40 ignored paths

func (s *Server) uiRepoIgnoredPathAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pattern string `json:"pattern"`
	}
	if !uiDecodeBody(w, r, &body) {
		return
	}
	s.uiRepoIgnoredPathEdit(w, r, body.Pattern, true)
}

func (s *Server) uiRepoIgnoredPathDelete(w http.ResponseWriter, r *http.Request) {
	s.uiRepoIgnoredPathEdit(w, r, r.URL.Query().Get("pattern"), false)
}

func (s *Server) uiRepoIgnoredPathEdit(w http.ResponseWriter, r *http.Request, pattern string, add bool) {
	repo, ok := s.uiLoadRepo(w, r, "scan_config")
	if !ok {
		return
	}
	changed, err := s.editIgnoredPath(repo, pattern, add)
	var inputErr scanConfigInputError
	switch {
	case errors.As(err, &inputErr):
		uiBadParam(w, err.Error())
		return
	case err != nil:
		uiInternal(w, err)
		return
	}
	if changed {
		s.publishRepository(repo.ID, uiChangeUpdated)
	}
	if err := s.DB.Select("id", "scan_config").First(&repo, repo.ID).Error; err != nil {
		uiInternal(w, err)
		return
	}
	writeUIJSON(w, http.StatusOK, uiScanConfigView(repo, &changed))
}

// ---------------------------------------------------------------- #41 alternatives

func (s *Server) uiRepoAlternativeCreate(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	var body struct {
		PURL string `json:"purl"`
		Kind string `json:"kind"`
		Note string `json:"note"`
	}
	if !uiDecodeBody(w, r, &body) {
		return
	}
	row, err := buildPackageAlternative(repo.ID, body.PURL, body.Kind, body.Note)
	if err != nil {
		field := "purl"
		if strings.HasPrefix(err.Error(), "kind") {
			field = "kind"
		}
		writeUIFields(w, uiFieldErrors{field: err.Error()})
		return
	}
	if err := s.DB.Create(&row).Error; err != nil {
		uiInternal(w, err)
		return
	}
	s.publishRepository(repo.ID, uiChangeUpdated)
	writeUIJSON(w, http.StatusCreated, packageAlternativeResponses([]db.PackageAlternative{row})[0])
}

func (s *Server) uiRepoAlternativeDelete(w http.ResponseWriter, r *http.Request) {
	s.uiRepoChildDelete(w, r, "alternative_id", "alternative", &db.PackageAlternative{})
}

// uiRepoChildDelete deletes one repository-scoped row named by the path
// param, 404 when it is absent or belongs to another repository.
func (s *Server) uiRepoChildDelete(w http.ResponseWriter, r *http.Request, param, what string, model any) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	childID, ok := uiPathID(w, r, param)
	if !ok {
		return
	}
	res := s.DB.Where("repository_id = ? AND id = ?", repo.ID, childID).Delete(model)
	if res.Error != nil {
		uiInternal(w, res.Error)
		return
	}
	if res.RowsAffected == 0 {
		uiNotFound(w, what)
		return
	}
	s.publishRepository(repo.ID, uiChangeUpdated)
	w.Header().Set(cacheControlHeader, noStore)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- #42 expected findings

func (s *Server) uiRepoExpectedCreate(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	var body struct {
		File string `json:"file"`
		CWE  string `json:"cwe"`
		CVE  string `json:"cve"`
		Note string `json:"note"`
	}
	if !uiDecodeBody(w, r, &body) {
		return
	}
	row, err := buildExpectedFinding(repo.ID, body.File, body.CWE, body.CVE, body.Note)
	if err != nil {
		field := "file"
		if strings.HasPrefix(err.Error(), uiKeyCWE) {
			field = uiKeyCWE
		}
		writeUIFields(w, uiFieldErrors{field: err.Error()})
		return
	}
	if err := s.DB.Create(&row).Error; err != nil {
		uiInternal(w, err)
		return
	}
	s.publishRepository(repo.ID, uiChangeUpdated)
	set := s.uiRepoExpectedMatches(repo.ID)
	for _, e := range set.Expected {
		if e.Expected.ID == row.ID {
			writeUIJSON(w, http.StatusCreated, uiExpectedRow(e))
			return
		}
	}
	writeUIJSON(w, http.StatusCreated, uiExpectedRow(expectedFindingStatus{Expected: row}))
}

func (s *Server) uiRepoExpectedDelete(w http.ResponseWriter, r *http.Request) {
	s.uiRepoChildDelete(w, r, "expected_id", "expected finding", &db.ExpectedFinding{})
}

// ---------------------------------------------------------------- #44 subproject channel

func (s *Server) uiSubprojectPatch(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return
	}
	sub, ok := s.uiLoadSubproject(w, r, repo.ID)
	if !ok {
		return
	}
	var body struct {
		DisclosureChannel *string `json:"disclosure_channel"`
	}
	if !uiDecodeBody(w, r, &body) {
		return
	}
	if body.DisclosureChannel == nil {
		writeUIFields(w, uiFieldErrors{"disclosure_channel": "required"})
		return
	}
	value := strings.TrimSpace(*body.DisclosureChannel)
	if err := db.SetSubprojectDisclosureChannel(s.DB, sub.ID, value, db.SourceAnalyst, ""); err != nil {
		uiInternal(w, err)
		return
	}
	if err := s.DB.First(&sub, sub.ID).Error; err != nil {
		uiInternal(w, err)
		return
	}
	s.publishRepository(repo.ID, uiChangeUpdated)
	view := s.loadRepoSubprojectView(repo.ID)
	writeUIJSON(w, http.StatusOK, map[string]any{
		"subproject": uiSubprojectRow(sub, view.ScanCount[sub.ScanSubPath()]),
		"disclosure_channel": map[string]string{
			"own": sub.DisclosureChannel, "effective": db.EffectiveDisclosureChannel(s.DB, repo.ID, sub.Path),
		},
	})
}
