package web

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

type uiSettingsJSON struct {
	ModelTiers    map[string]string `json:"model_tiers"`
	DefaultModel  string            `json:"default_model"`
	DefaultEffort string            `json:"default_effort"`
	Volatile      []string          `json:"volatile"`
	Concurrency   struct {
		Saved     int `json:"saved"`
		Input     int `json:"input"`
		Effective int `json:"effective"`
		Live      int `json:"live"`
	} `json:"concurrency"`
	DefaultMaxTurns int      `json:"default_max_turns"`
	BuiltinMaxTurns int      `json:"builtin_max_turns"`
	ScanSchedule    string   `json:"scan_schedule"`
	Theme           string   `json:"theme"`
	ColorScheme     string   `json:"color_scheme"`
	Themes          []string `json:"themes"`
	Models          []struct {
		Value string `json:"value"`
	} `json:"models"`
	Stats struct {
		Repos  int64 `json:"repos"`
		Skills int64 `json:"skills"`
	} `json:"stats"`
	Runner struct {
		Backend string            `json:"backend"`
		Tools   map[string]string `json:"tools"`
	} `json:"runner"`
	Version struct {
		Version string `json:"version"`
	} `json:"version"`

	RestartRequired *bool `json:"concurrency_restart_required"`
	Outcome         *struct {
		Applied         bool  `json:"applied"`
		RestartRequired bool  `json:"restart_required"`
		Running         int64 `json:"running"`
	} `json:"concurrency_outcome"`
}

func patchSettings(t *testing.T, body any) *http.Request {
	t.Helper()
	return operatorReq(t, http.MethodPatch, "/api/v1/ui/settings", body)
}

func TestUISettingsShow(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Version = "v-test"
	seedUIRepo(t, s.DB, "r")
	if err := db.SetSetting(s.DB, db.SettingScanSchedule, "daily"); err != nil {
		t.Fatal(err)
	}

	got := decodeUIJSON[uiSettingsJSON](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/settings", nil)), http.StatusOK)
	if !slices.Equal(got.Volatile, []string{"default_model", "default_effort"}) {
		t.Errorf("volatile = %v", got.Volatile)
	}
	if got.DefaultModel != s.DefaultModel() || got.DefaultEffort != s.DefaultEffort() || len(got.ModelTiers) != len(ModelTiers) {
		t.Errorf("models = %+v", got)
	}
	if got.Concurrency.Saved != 0 || got.Concurrency.Live != s.Queue.Concurrency() || got.Concurrency.Input != got.Concurrency.Live {
		t.Errorf("concurrency = %+v", got.Concurrency)
	}
	if got.ScanSchedule != "daily" || got.BuiltinMaxTurns == 0 || got.Theme != defaultTheme || got.ColorScheme != "system" {
		t.Errorf("view = %+v", got)
	}
	if got.Stats.Repos != 1 || got.Version.Version != "v-test" || got.Runner.Backend != s.Backend || len(got.Runner.Tools) != 5 {
		t.Errorf("stats/runner/version = %+v %+v %+v", got.Stats, got.Runner, got.Version)
	}
	if got.RestartRequired != nil {
		t.Error("GET carries concurrency_restart_required")
	}
}

func TestUISettingsPatch(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	sub := s.Broker.Subscribe(0, 0, 0, uiMetaEvent)
	defer s.Broker.Unsubscribe(sub)
	model := Models[len(Models)-1].ID

	w := serveUI(t, s, patchSettings(t, map[string]any{
		"model_tiers":       map[string]any{"mid": model},
		"default_model":     model,
		"default_effort":    "low",
		"default_max_turns": 77,
		"scan_schedule":     "weekly",
		"theme":             "catppuccin",
		"color_scheme":      "dark",
	}))
	got := decodeUIJSON[uiSettingsJSON](t, w, http.StatusOK)
	if got.ModelTiers[ModelTierMid] != model || got.DefaultModel != model || got.DefaultEffort != "low" ||
		got.DefaultMaxTurns != 77 || got.ScanSchedule != "weekly" || got.Theme != "catppuccin" || got.ColorScheme != "dark" {
		t.Errorf("patched view = %+v", got)
	}
	if got.RestartRequired == nil || *got.RestartRequired || got.Outcome != nil {
		t.Errorf("restart_required = %v outcome = %v, want false / null", got.RestartRequired, got.Outcome)
	}
	if v, _ := db.GetSetting(s.DB, db.SettingModelTierMid); v != model {
		t.Errorf("mid tier persisted = %q", v)
	}
	if db.SettingInt(s.DB, db.SettingDefaultMaxTurns) != 77 || s.DefaultEffort() != "low" || s.DefaultModel() != model {
		t.Error("settings not applied")
	}
	cookies := w.Result().Cookies()
	var names []string
	for _, c := range cookies {
		names = append(names, c.Name+"="+c.Value)
	}
	if !slices.Contains(names, "theme=catppuccin") || !slices.Contains(names, "color_scheme=dark") {
		t.Errorf("cookies = %v", names)
	}
	if changed := waitMetaEvent(t, sub); !slices.Equal(changed, []string{"models"}) {
		t.Errorf("meta changed = %v", changed)
	}

	// Effort alone is not a model change.
	decodeUIJSON[uiSettingsJSON](t, serveUI(t, s, patchSettings(t, map[string]any{"default_effort": "max"})), http.StatusOK)
	requireNoEvent(t, sub)

	// "off" clears the schedule.
	got = decodeUIJSON[uiSettingsJSON](t, serveUI(t, s, patchSettings(t, map[string]any{"scan_schedule": "off"})), http.StatusOK)
	if got.ScanSchedule != "" {
		t.Errorf("scan_schedule after off = %q", got.ScanSchedule)
	}
}

func TestUISettingsPatchValidation(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	// One bad field rejects the whole body: the valid max turns is not written.
	e := requireUIError(t, serveUI(t, s, patchSettings(t, map[string]any{
		"default_max_turns": 40,
		"concurrency":       0,
		"default_effort":    "ludicrous",
		"default_model":     "gpt-0",
		"model_tiers":       map[string]any{"max": "gpt-0"},
		"scan_schedule":     "every tuesday",
		"theme":             "neon",
		"color_scheme":      "sepia",
	})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	for _, f := range []string{"concurrency", "default_effort", "default_model", "model_tiers.max", "scan_schedule", "theme", "color_scheme"} {
		if e.Fields[f] == "" {
			t.Errorf("fields = %v, missing %q", e.Fields, f)
		}
	}
	if db.SettingInt(s.DB, db.SettingDefaultMaxTurns) != 0 {
		t.Error("valid field written despite a 422")
	}
	for _, n := range []int{0, 501} {
		requireUIError(t, serveUI(t, s, patchSettings(t, map[string]any{"default_max_turns": n})),
			http.StatusUnprocessableEntity, uiCodeValidationFailed)
	}
	requireUIError(t, serveUI(t, s, patchSettings(t, map[string]any{"concurency": 4})), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, serveUI(t, s, patchSettings(t, map[string]any{"model_tiers": map[string]any{"huge": "x"}})),
		http.StatusBadRequest, uiCodeBadParam)
}

func TestUISettingsPatchConcurrency(t *testing.T) {
	t.Run("idle applies", func(t *testing.T) {
		s, done := newTestServer(t)
		defer done()
		got := decodeUIJSON[uiSettingsJSON](t, serveUI(t, s, patchSettings(t, map[string]any{"concurrency": 12})), http.StatusOK)
		if got.Outcome == nil || !got.Outcome.Applied || *got.RestartRequired || s.Queue.Concurrency() != 12 {
			t.Errorf("outcome = %+v, live = %d", got.Outcome, s.Queue.Concurrency())
		}
		if got.Concurrency.Saved != 12 || got.Concurrency.Live != 12 {
			t.Errorf("concurrency view = %+v", got.Concurrency)
		}
	})
	t.Run("running needs confirmation", func(t *testing.T) {
		s, done := newTestServer(t)
		defer done()
		repo := seedUIRepo(t, s.DB, "busy")
		seedUIScan(t, s.DB, repo, db.ScanRunning, "semgrep")
		before := s.Queue.Concurrency()
		got := decodeUIJSON[uiSettingsJSON](t, serveUI(t, s, patchSettings(t, map[string]any{"concurrency": 20})), http.StatusOK)
		if got.RestartRequired == nil || !*got.RestartRequired || got.Outcome == nil || got.Outcome.Running != 1 || got.Outcome.Applied {
			t.Errorf("outcome = %+v restart_required = %v", got.Outcome, got.RestartRequired)
		}
		if db.SettingInt(s.DB, db.SettingConcurrency) != 20 || s.Queue.Concurrency() != before {
			t.Errorf("saved = %d live = %d (was %d): want saved, not applied",
				db.SettingInt(s.DB, db.SettingConcurrency), s.Queue.Concurrency(), before)
		}
	})
	t.Run("capped is saved only", func(t *testing.T) {
		s, done := newTestServer(t)
		defer done()
		s.Queue.SetMaxConcurrency(1)
		s.Queue.Reconfigure(1)
		got := decodeUIJSON[uiSettingsJSON](t, serveUI(t, s, patchSettings(t, map[string]any{"concurrency": 20})), http.StatusOK)
		if got.Outcome == nil || got.Outcome.Applied || got.Outcome.RestartRequired || s.Queue.Concurrency() != 1 {
			t.Errorf("outcome = %+v live = %d", got.Outcome, s.Queue.Concurrency())
		}
	})
}

func TestUISettingsRestartRunner(t *testing.T) {
	type result struct {
		Restarted   bool   `json:"restarted"`
		Concurrency int    `json:"concurrency"`
		Note        string `json:"note"`
	}
	t.Run("restarts at the saved value", func(t *testing.T) {
		s, done := newTestServer(t)
		t.Cleanup(done)
		s.Queue.Reconfigure(4)
		if err := db.SetSetting(s.DB, db.SettingConcurrency, "9"); err != nil {
			t.Fatal(err)
		}
		jobCtx := startSettingsRunnerJob(t, s)
		got := decodeUIJSON[result](t, serveUI(t, s,
			operatorReq(t, http.MethodPost, "/api/v1/ui/settings/actions/restart-runner", nil)), http.StatusAccepted)
		if !got.Restarted || got.Concurrency != 9 || s.Queue.Concurrency() != 9 {
			t.Errorf("result = %+v live = %d", got, s.Queue.Concurrency())
		}
		if jobCtx.Err() == nil {
			t.Error("running job not cancelled by the restart")
		}
	})
	t.Run("capped is a no-op", func(t *testing.T) {
		s, done := newTestServer(t)
		t.Cleanup(done)
		s.Queue.Reconfigure(4)
		s.Queue.SetMaxConcurrency(1)
		if err := db.SetSetting(s.DB, db.SettingConcurrency, "16"); err != nil {
			t.Fatal(err)
		}
		jobCtx := startSettingsRunnerJob(t, s)
		got := decodeUIJSON[result](t, serveUI(t, s,
			operatorReq(t, http.MethodPost, "/api/v1/ui/settings/actions/restart-runner", nil)), http.StatusAccepted)
		if got.Restarted || !strings.Contains(got.Note, "stays at 1") || jobCtx.Err() != nil {
			t.Errorf("result = %+v, cancelled = %v", got, jobCtx.Err() != nil)
		}
	})
}
