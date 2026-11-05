package web

import (
	"net/http"
	"slices"
	"strconv"
	"strings"

	"scrutineer/internal/config"
	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

// Settings (02 #89-#91, F-SET-01..10). Settings are key/value rows with no
// single version, so PATCH is last-write-wins and ignores If-Match. The
// default model and effort live in process memory only (SetDefaultModel /
// SetDefaultEffort, reverted by a restart); GET lists them under `volatile`
// so the SPA can say so. Theme and colour scheme are the legacy cookies,
// set on the PATCH response so both UIs agree.

const (
	uiSettingsDefaultModel  = "default_model"
	uiSettingsDefaultEffort = "default_effort"
	uiSettingsConcurrency   = "concurrency"
	uiSettingsMaxTurns      = "default_max_turns"
	uiSettingsScanSchedule  = "scan_schedule"
	uiSettingsTheme         = "theme"
	uiSettingsColorScheme   = "color_scheme"
	uiSettingsModelsChanged = "models"
	uiSettingsCommitKey     = "commit"
)

// uiSettingsTierBody is the model_tiers part of a PATCH; nil = unchanged.
type uiSettingsTierBody struct {
	Mid  *string `json:"mid"`
	High *string `json:"high"`
	Max  *string `json:"max"`
}

// byTier pairs each sent tier with its value, in ModelTiers order.
func (t *uiSettingsTierBody) byTier() map[string]string {
	out := map[string]string{}
	if t == nil {
		return out
	}
	for tier, v := range map[string]*string{ModelTierMid: t.Mid, ModelTierHigh: t.High, ModelTierMax: t.Max} {
		if v != nil {
			out[tier] = strings.TrimSpace(*v)
		}
	}
	return out
}

type uiSettingsPatchBody struct {
	ModelTiers      *uiSettingsTierBody `json:"model_tiers"`
	DefaultModel    *string             `json:"default_model"`
	DefaultEffort   *string             `json:"default_effort"`
	Concurrency     *int                `json:"concurrency"`
	DefaultMaxTurns *int                `json:"default_max_turns"`
	ScanSchedule    *string             `json:"scan_schedule"`
	Theme           *string             `json:"theme"`
	ColorScheme     *string             `json:"color_scheme"`
}

// uiConcurrencyOutcome reports what a concurrency write did (see
// concurrencyOutcome); restart_required is the HTML page's confirm panel.
type uiConcurrencyOutcome struct {
	Applied         bool   `json:"applied"`
	RestartRequired bool   `json:"restart_required"`
	Running         int64  `json:"running"`
	Note            string `json:"note"`
}

// ---------------------------------------------------------------- GET

func uiSettingsModels() []map[string]string {
	out := make([]map[string]string, len(Models))
	for i, m := range Models {
		out[i] = map[string]string{labelValueKey: m.ID, labelLabelKey: m.Name, "tier": m.Tier}
	}
	return out
}

func uiSettingsTiers() []map[string]string {
	out := make([]map[string]string, len(ModelTiers))
	for i, t := range ModelTiers {
		out[i] = map[string]string{labelValueKey: t.Value, labelLabelKey: t.Name, uiSkillDescKey: t.Description}
	}
	return out
}

func (s *Server) uiSettingsConcurrency() map[string]any {
	input := s.concurrencyInput()
	effective := s.Queue.EffectiveConcurrency(input)
	return map[string]any{
		"saved":       db.SettingInt(s.DB, db.SettingConcurrency),
		"input":       input,
		"effective":   effective,
		"live":        s.Queue.Concurrency(),
		"capped_note": cappedConcurrencyNote(input, effective),
	}
}

func uiSettingsRunner(meta toolMetadata) map[string]any {
	return map[string]any{
		"image":        meta.RunnerImage,
		"image_ref":    meta.RunnerImageRef(),
		"revision":     meta.Revision,
		"backend":      meta.Backend,
		"harness":      meta.Harness,
		"stale":        meta.Stale,
		"stale_days":   meta.StaleDays,
		"pull_command": meta.PullCommand,
		"tools": map[string]string{
			"semgrep": meta.Semgrep, "zizmor": meta.Zizmor, "bandit": meta.Bandit,
			"betterleaks": meta.Betterleaks, "container_runtime": meta.Runtime,
		},
	}
}

// uiSettingsView is the GET /ui/settings document. theme and colorScheme are
// passed in so a PATCH can report the cookie values it just set.
func (s *Server) uiSettingsView(r *http.Request, theme, colorScheme string) map[string]any {
	sizeBytes, dbPath := s.databaseSizeAndPath()
	scanSchedule, _ := db.GetSetting(s.DB, db.SettingScanSchedule)
	workDir := ""
	if s.Worker != nil {
		workDir = s.Worker.DataDir
	}
	return map[string]any{
		"model_tiers":           ModelTierValues(s.DB, s.DefaultModel()),
		uiSettingsDefaultModel:  s.DefaultModel(),
		uiSettingsDefaultEffort: s.DefaultEffort(),
		"volatile":              []string{uiSettingsDefaultModel, uiSettingsDefaultEffort},
		uiSettingsConcurrency:   s.uiSettingsConcurrency(),
		uiSettingsMaxTurns:      db.SettingInt(s.DB, db.SettingDefaultMaxTurns),
		"builtin_max_turns":     worker.DefaultSkillMaxTurns,
		uiSettingsScanSchedule:  scanSchedule,
		"limits": map[string]any{
			uiSettingsConcurrency: map[string]int{"min": minConcurrency, "max": maxConcurrency},
			uiSettingsMaxTurns:    map[string]int{"min": minMaxTurns, "max": maxMaxTurns},
		},
		uiSettingsTheme:       theme,
		uiSettingsColorScheme: colorScheme,
		"themes":              config.Themes,
		"color_schemes":       colorSchemes,
		"models":              uiSettingsModels(),
		"efforts":             uiEfforts(),
		"tiers":               uiSettingsTiers(),
		"runner":              uiSettingsRunner(s.runnerMetadata(r.Context())),
		"stats":               s.settingsStats(),
		"db":                  map[string]any{"size_bytes": sizeBytes, "path": dbPath},
		"work_dir":            workDir,
		"version":             map[string]string{"version": s.Version, uiSettingsCommitKey: s.Commit, "commit_date": s.CommitDate},
	}
}

func (s *Server) uiSettingsShow(w http.ResponseWriter, r *http.Request) {
	writeUIJSON(w, http.StatusOK, s.uiSettingsView(r, resolveTheme(r), resolveColorScheme(r)))
}

// ---------------------------------------------------------------- PATCH

// validateSettingsPatch checks every sent field before anything is written,
// so a 422 leaves all settings untouched.
func validateSettingsPatch(b *uiSettingsPatchBody) uiFieldErrors {
	errs := uiFieldErrors{}
	for tier, model := range b.ModelTiers.byTier() {
		if !ValidModel(model) {
			errs["model_tiers."+tier] = "unknown model"
		}
	}
	if b.DefaultModel != nil && !ValidModel(*b.DefaultModel) {
		errs[uiSettingsDefaultModel] = "unknown model"
	}
	if b.DefaultEffort != nil && !ValidEffort(*b.DefaultEffort) {
		errs[uiSettingsDefaultEffort] = "unknown effort"
	}
	if n := b.Concurrency; n != nil && (*n < minConcurrency || *n > maxConcurrency) {
		errs[uiSettingsConcurrency] = "must be between " + strconv.Itoa(minConcurrency) + " and " + strconv.Itoa(maxConcurrency)
	}
	if n := b.DefaultMaxTurns; n != nil && (*n < minMaxTurns || *n > maxMaxTurns) {
		errs[uiSettingsMaxTurns] = "must be between " + strconv.Itoa(minMaxTurns) + " and " + strconv.Itoa(maxMaxTurns)
	}
	if b.ScanSchedule != nil {
		if _, err := normalizeScanSchedule(strings.TrimSpace(*b.ScanSchedule)); err != nil {
			errs[uiSettingsScanSchedule] = "invalid schedule: " + err.Error()
		}
	}
	if b.Theme != nil && (*b.Theme == "" || config.ValidateTheme(*b.Theme) != nil) {
		errs[uiSettingsTheme] = "unknown theme"
	}
	if b.ColorScheme != nil && !slices.Contains(colorSchemes, *b.ColorScheme) {
		errs[uiSettingsColorScheme] = "unknown color scheme"
	}
	if len(errs) == 0 {
		return nil
	}
	return errs
}

// applySettingsPersisted writes the db-backed settings: model tiers, default
// turns and the scan schedule. Concurrency is applied separately because it
// has an outcome to report.
func (s *Server) applySettingsPersisted(b *uiSettingsPatchBody) error {
	for tier, model := range b.ModelTiers.byTier() {
		if err := db.SetSetting(s.DB, modelTierSettingKey(tier), model); err != nil {
			return err
		}
	}
	if b.DefaultMaxTurns != nil {
		if err := db.SetSetting(s.DB, db.SettingDefaultMaxTurns, strconv.Itoa(*b.DefaultMaxTurns)); err != nil {
			return err
		}
	}
	if b.ScanSchedule != nil {
		schedule, _ := normalizeScanSchedule(strings.TrimSpace(*b.ScanSchedule)) // validated
		if err := s.saveScanSchedule(schedule); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) uiSettingsPatch(w http.ResponseWriter, r *http.Request) {
	var body uiSettingsPatchBody
	if !decodeInsightBody(w, r, &body) {
		return
	}
	if errs := validateSettingsPatch(&body); errs != nil {
		writeUIFields(w, errs)
		return
	}
	if err := s.applySettingsPersisted(&body); err != nil {
		uiInternal(w, err)
		return
	}
	if body.DefaultModel != nil {
		s.SetDefaultModel(*body.DefaultModel)
	}
	if body.DefaultEffort != nil {
		s.SetDefaultEffort(*body.DefaultEffort)
	}
	var outcome *uiConcurrencyOutcome
	if body.Concurrency != nil {
		out, err := s.saveConcurrency(*body.Concurrency)
		if err != nil {
			uiInternal(w, err)
			return
		}
		outcome = &uiConcurrencyOutcome{
			Applied: out.Applied, RestartRequired: out.RestartRequired, Running: out.Running, Note: out.Note,
		}
	}
	theme, scheme := resolveTheme(r), resolveColorScheme(r)
	if body.Theme != nil {
		theme = *body.Theme
		setThemeCookie(w, theme)
	}
	if body.ColorScheme != nil {
		scheme = *body.ColorScheme
		setColorSchemeCookie(w, scheme)
	}
	if body.ModelTiers != nil || body.DefaultModel != nil {
		s.publishMeta(uiSettingsModelsChanged)
	}
	view := s.uiSettingsView(r, theme, scheme)
	view["concurrency_restart_required"] = outcome != nil && outcome.RestartRequired
	view["concurrency_outcome"] = outcome
	writeUIJSON(w, http.StatusOK, view)
}

// ---------------------------------------------------------------- restart

// uiSettingsRestartRunner rebuilds the runner at the saved concurrency,
// cancelling in-flight scans (queued scans survive). restarted is false, with
// the cap explained in note, when a backend cap means nothing would change.
func (s *Server) uiSettingsRestartRunner(w http.ResponseWriter, _ *http.Request) {
	restarted, note := s.restartRunner()
	writeUIJSON(w, http.StatusAccepted, map[string]any{
		"restarted":           restarted,
		uiSettingsConcurrency: s.Queue.Concurrency(),
		"note":                note,
	})
}
