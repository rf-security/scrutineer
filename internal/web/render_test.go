package web

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// A template error raised after some output has already been produced must
// still yield a clean 500. Executing straight into the ResponseWriter commits
// a 200 plus the partial HTML before the error is known, so the http.Error
// that follows cannot change the status and only appends plain text to a
// half-rendered page (#573).
func TestRenderTemplateErrorAfterPartialOutput(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	const marker = "PARTIAL-OUTPUT-MARKER"
	_, err := s.tmpl.New("boom_test.html").
		Funcs(map[string]any{
			"boom": func() (string, error) { return "", errors.New("boom") },
		}).
		Parse(`<!doctype html><title>t</title><div>` + marker + `</div>{{ boom }}`)
	if err != nil {
		t.Fatalf("parse test template: %v", err)
	}

	w := httptest.NewRecorder()
	s.render(w, localReq("GET", "/"), "boom_test.html", nil)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if got := w.Body.String(); strings.Contains(got, marker) {
		t.Errorf("response carries partially rendered HTML; body starts: %q", got[:min(len(got), 120)])
	}
	if ct := w.Header().Get("Content-Type"); strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want the plain-text error type, not HTML", ct)
	}
}

// The success path is unchanged apart from now being able to declare its
// length, since the whole body is known before anything is written.
func TestRenderSuccessSetsHTMLHeaders(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	const body = "<!doctype html><title>ok</title><p>hello</p>"
	if _, err := s.tmpl.New("ok_test.html").Parse(body); err != nil {
		t.Fatalf("parse test template: %v", err)
	}

	w := httptest.NewRecorder()
	s.render(w, localReq("GET", "/"), "ok_test.html", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Body.String(); got != body {
		t.Errorf("body = %q, want %q", got, body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cl := w.Header().Get("Content-Length"); cl != strconv.Itoa(len(body)) {
		t.Errorf("Content-Length = %q, want %d", cl, len(body))
	}
}

// Buffers are pooled and a failed render hands its buffer back with the
// partial page still in it, so the reset in render() is what stops that page
// reaching the next request. Success alone cannot show this: WriteTo drains
// the buffer on its way out, so a success-then-success pair leaves nothing to
// leak either way.
func TestRenderPooledBufferDoesNotLeakFailedPageIntoNextRender(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	const leak = "LEAK-FROM-FAILED-PAGE"
	if _, err := s.tmpl.New("leak_boom_test.html").
		Funcs(map[string]any{
			"boom": func() (string, error) { return "", errors.New("boom") },
		}).
		Parse(leak + strings.Repeat("y", 4<<10) + `{{ boom }}`); err != nil {
		t.Fatalf("parse failing template: %v", err)
	}
	if _, err := s.tmpl.New("leak_small_test.html").Parse("small"); err != nil {
		t.Fatalf("parse small template: %v", err)
	}

	s.render(httptest.NewRecorder(), localReq("GET", "/"), "leak_boom_test.html", nil)

	w := httptest.NewRecorder()
	s.render(w, localReq("GET", "/"), "leak_small_test.html", nil)

	if got := w.Body.String(); got != "small" {
		t.Errorf("body = %q, want %q — the failed render's buffer reached the next request",
			got[:min(len(got), 80)], "small")
	}
	// The leak is served as a well-formed response rather than a truncated
	// one, so nothing downstream would flag it.
	if cl := w.Header().Get("Content-Length"); cl != strconv.Itoa(len("small")) {
		t.Errorf("Content-Length = %q, want %d", cl, len("small"))
	}
}

// Every full page template must close what "head" opened. "head" emits the
// document, the sidebar and an unclosed <main><div>; only "foot" closes them
// and emits the shared dialogs plus the #toaster that flash messages and
// htmx OOB toasts are swapped into. A page that opens with "head" and never
// calls "foot" still parses, still renders 200 and still looks right in a
// browser that forgives unclosed tags — it just silently drops the toaster
// and the dialogs. Nothing else in the build catches that, so assert the
// pairing here (#reporting shipped without it). Fragment templates invoke
// neither and are left alone.
func TestPageTemplatesCloseTheLayoutTheyOpen(t *testing.T) {
	const (
		head = `{{template "head" .}}`
		foot = `{{template "foot" .}}`
	)
	entries, err := fs.ReadDir(tmplFS, "templates")
	if err != nil {
		t.Fatal(err)
	}
	var pages int
	for _, entry := range entries {
		body, err := fs.ReadFile(tmplFS, "templates/"+entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		opens := strings.Count(string(body), head)
		closes := strings.Count(string(body), foot)
		if opens == 0 && closes == 0 {
			continue
		}
		pages++
		if opens != closes {
			t.Errorf("%s: %d %s but %d %s", entry.Name(), opens, head, closes, foot)
		}
	}
	if pages == 0 {
		t.Fatal("no page templates found; the head/foot spelling must have changed")
	}
}
