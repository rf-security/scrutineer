package web

import (
	"net/http"
	"slices"
	"strconv"
	"testing"
	"time"

	"scrutineer/internal/db"
)

type uiSkillJSON struct {
	ID          uint      `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Body        string    `json:"body"`
	SchemaJSON  string    `json:"schema_json"`
	OutputKind  string    `json:"output_kind"`
	Model       string    `json:"model"`
	MaxTurns    int       `json:"max_turns"`
	Version     int       `json:"version"`
	Active      bool      `json:"active"`
	Source      string    `json:"source"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func seedUISkill(t *testing.T, s *Server, name string, active bool) db.Skill {
	t.Helper()
	sk := db.Skill{Name: name, Description: name + " skill", Body: "# " + name, Version: 1, Active: true, Source: "disk"}
	if err := s.DB.Create(&sk).Error; err != nil {
		t.Fatal(err)
	}
	if !active {
		// Active has a db default of true, so false must be written explicitly.
		if err := s.DB.Model(&sk).Update("active", false).Error; err != nil {
			t.Fatal(err)
		}
		sk.Active = false
	}
	if err := s.DB.First(&sk, sk.ID).Error; err != nil {
		t.Fatal(err)
	}
	return sk
}

func skillPath(id uint) string { return "/api/v1/ui/skills/" + strconv.FormatUint(uint64(id), 10) }

func TestUISkillsList(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedUISkill(t, s, "zeta", true)
	seedUISkill(t, s, "alpha", false)
	seedUISkill(t, s, "beta", true)

	names := func(rows []uiSkillJSON) []string {
		out := make([]string, len(rows))
		for i, r := range rows {
			out[i] = r.Name
		}
		return out
	}
	all := decodeUIJSON[[]uiSkillJSON](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/skills", nil)), http.StatusOK)
	if got := names(all); !slices.Equal(got, []string{"beta", "zeta", "alpha"}) {
		t.Errorf("order = %v, want active first then name", got)
	}
	if all[0].Body != "" {
		t.Errorf("list rows carry the body: %q", all[0].Body)
	}
	inactive := decodeUIJSON[[]uiSkillJSON](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/skills?active=false", nil)), http.StatusOK)
	if got := names(inactive); !slices.Equal(got, []string{"alpha"}) {
		t.Errorf("active=false = %v", got)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/skills?active=yes", nil)),
		http.StatusBadRequest, uiCodeBadParam)
}

func TestUISkillShow(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	sk := seedUISkill(t, s, "show-me", true)

	w := serveUI(t, s, operatorReq(t, http.MethodGet, skillPath(sk.ID), nil))
	got := decodeUIJSON[uiSkillJSON](t, w, http.StatusOK)
	if got.Name != "show-me" || got.Body != "# show-me" || got.Source != "disk" {
		t.Errorf("detail = %+v", got)
	}
	if w.Header().Get("ETag") != etagFor(sk.UpdatedAt) {
		t.Errorf("ETag = %q, want %q", w.Header().Get("ETag"), etagFor(sk.UpdatedAt))
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, skillPath(9999), nil)), http.StatusNotFound, uiCodeNotFound)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/skills/x", nil)), http.StatusBadRequest, uiCodeBadParam)
}

func TestUISkillCreate(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	sub := s.Broker.Subscribe(0, 0, 0, uiMetaEvent)
	defer s.Broker.Unsubscribe(sub)

	body := map[string]any{
		"name": " new-skill ", "description": "Does things", "body": "# Prompt\n", "max_turns": 12,
		"model": ModelTierHigh, "schema_json": `{"type":"object"}`,
	}
	w := serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/skills", body))
	got := decodeUIJSON[uiSkillJSON](t, w, http.StatusCreated)
	if got.ID == 0 || got.Name != "new-skill" || !got.Active || got.Version != 1 || got.Source != "ui" ||
		got.MaxTurns != 12 || got.Model != ModelTierHigh || got.Body != "# Prompt\n" {
		t.Errorf("created = %+v", got)
	}
	if w.Header().Get("ETag") == "" {
		t.Error("create response has no ETag")
	}
	if changed := waitMetaEvent(t, sub); !slices.Equal(changed, []string{"skills"}) {
		t.Errorf("meta changed = %v", changed)
	}

	for name, tc := range map[string]struct {
		body  map[string]any
		field string
	}{
		"bad name":       {map[string]any{"name": "Bad_Name", "description": "d"}, "name"},
		"long name":      {map[string]any{"name": longString(uiSkillNameMax + 1), "description": "d"}, "name"},
		"no description": {map[string]any{"name": "ok-name"}, "description"},
		"bad kind":       {map[string]any{"name": "ok-name", "description": "d", "output_kind": "nope"}, "output_kind"},
		"bad model":      {map[string]any{"name": "ok-name", "description": "d", "model": "gpt-0"}, "model"},
		"bad schema":     {map[string]any{"name": "ok-name", "description": "d", "schema_json": "{"}, "schema_json"},
		"bad file":       {map[string]any{"name": "ok-name", "description": "d", "output_file": "../x.json"}, "output_file"},
		"negative turns": {map[string]any{"name": "ok-name", "description": "d", "max_turns": -1}, "max_turns"},
		"duplicate":      {map[string]any{"name": "new-skill", "description": "d"}, "name"},
	} {
		t.Run(name, func(t *testing.T) {
			e := requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/skills", tc.body)),
				http.StatusUnprocessableEntity, uiCodeValidationFailed)
			if e.Fields[tc.field] == "" {
				t.Errorf("fields = %v, want %q", e.Fields, tc.field)
			}
		})
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/skills",
		map[string]any{"name": "x", "description": "d", "active": false})), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/skills", "{")), http.StatusBadRequest, uiCodeBadParam)
}

func longString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

func TestUISkillPatch(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	sk := seedUISkill(t, s, "editable", true)
	seedUISkill(t, s, "taken", true)
	sub := s.Broker.Subscribe(0, 0, 0, uiMetaEvent)
	defer s.Broker.Unsubscribe(sub)

	patch := func(body any, etag string) *http.Request {
		r := operatorReq(t, http.MethodPatch, skillPath(sk.ID), body)
		if etag != "" {
			r.Header.Set("If-Match", etag)
		}
		return r
	}

	// A real change bumps the version and the ETag and announces itself.
	w := serveUI(t, s, patch(map[string]any{"description": "Sharper"}, etagFor(sk.UpdatedAt)))
	got := decodeUIJSON[uiSkillJSON](t, w, http.StatusOK)
	if got.Description != "Sharper" || got.Version != 2 || got.Body != "# editable" {
		t.Fatalf("patched = %+v", got)
	}
	etag := w.Header().Get("ETag")
	if etag == "" || etag == etagFor(sk.UpdatedAt) {
		t.Errorf("ETag = %q, want a new version", etag)
	}
	if changed := waitMetaEvent(t, sub); !slices.Equal(changed, []string{"skills"}) {
		t.Errorf("meta changed = %v", changed)
	}

	// Re-sending the same value (a trailing debounced save) is a no-op.
	w = serveUI(t, s, patch(map[string]any{"description": "Sharper"}, etag))
	if again := decodeUIJSON[uiSkillJSON](t, w, http.StatusOK); again.Version != 2 || w.Header().Get("ETag") != etag {
		t.Errorf("no-op patch bumped: version %d etag %q", again.Version, w.Header().Get("ETag"))
	}
	requireNoEvent(t, sub)

	// The active toggle.
	w = serveUI(t, s, patch(map[string]any{"active": false}, ""))
	if off := decodeUIJSON[uiSkillJSON](t, w, http.StatusOK); off.Active || off.Version != 3 {
		t.Errorf("toggle = %+v", off)
	}
	var stored db.Skill
	s.DB.First(&stored, sk.ID)
	if stored.Active {
		t.Error("active=false not persisted")
	}

	// A stale If-Match is a conflict carrying the current row.
	e := decodeUIJSON[struct {
		Code    string      `json:"code"`
		Current uiSkillJSON `json:"current"`
	}](t, serveUI(t, s, patch(map[string]any{"description": "Lost"}, etag)), http.StatusConflict)
	if e.Code != uiCodeConflict || e.Current.Version != 3 || e.Current.Description != "Sharper" {
		t.Errorf("conflict = %+v", e)
	}

	requireUIError(t, serveUI(t, s, patch(map[string]any{"output_kind": "nope"}, "")),
		http.StatusUnprocessableEntity, uiCodeValidationFailed)
	requireUIError(t, serveUI(t, s, patch(map[string]any{"name": "taken"}, "")),
		http.StatusUnprocessableEntity, uiCodeValidationFailed)
	requireUIError(t, serveUI(t, s, patch(map[string]any{"bogus": 1}, "")), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPatch, skillPath(9999), map[string]any{"active": true})),
		http.StatusNotFound, uiCodeNotFound)
}
