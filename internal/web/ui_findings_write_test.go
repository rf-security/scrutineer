package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
)

// Tests for the WP-API-1 finding writes: PATCH, notes, communications,
// references, reviews, labels, campaign.

func patchFinding(t *testing.T, s *Server, id uint, body any, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := operatorReq(t, http.MethodPatch, findingPath(id, ""), body)
	for k, v := range header {
		r.Header.Set(k, v)
	}
	return serveUI(t, s, r)
}

func TestUIFindingPatchHappyPath(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fx := seedUIFindingFixture(t, s)
	events := captureUIEvents(t, s, uiFindingEvent)

	w := patchFinding(t, s, fx.high.ID, map[string]any{
		"fields": map[string]string{"assignee": " walter ", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			"disclosure_draft": "line one\r\nline two", "exploited_in_wild": "yes"},
		"by": "walter",
	}, nil)
	body := decodeUIJSON[map[string]any](t, w, http.StatusOK)
	if w.Header().Get("ETag") == "" {
		t.Fatal("PATCH must return the new ETag")
	}
	fields := body["fields"].(map[string]any)
	if fields["assignee"] != "walter" || fields["disclosure_draft"] != "line one\nline two" || fields["cvss_score"].(float64) != 9.8 {
		t.Fatalf("fields = %v", fields)
	}
	if _, ok := body["workflow"]; ok {
		t.Fatal("slim response must not carry the detail")
	}
	if body["assignee"] != "walter" || body["title_summary"] == nil {
		t.Fatalf("row = %v", body)
	}
	evs := events()
	if len(evs) != 1 {
		t.Fatalf("want exactly one finding event, got %d", len(evs))
	}
	if got := strings.Join(eventFields(t, evs[0]), ","); got != "assignee,cvss_vector,disclosure_draft,exploited_in_wild" {
		t.Fatalf("event fields = %s", got)
	}
	var hist []db.FindingHistory
	s.DB.Where("finding_id = ? AND field = ?", fx.high.ID, "assignee").Find(&hist)
	if len(hist) != 1 || hist[0].Source != db.SourceAnalyst || hist[0].By != "walter" {
		t.Fatalf("history = %+v", hist)
	}

	// Idempotent retry: no-op, no event.
	w = patchFinding(t, s, fx.high.ID, map[string]any{"fields": map[string]string{"assignee": "walter"}}, nil)
	decodeUIJSON[map[string]any](t, w, http.StatusOK)
	if evs := events(); len(evs) != 0 {
		t.Fatalf("no-op PATCH published %d events", len(evs))
	}

	// Prefer: return=representation yields the detail.
	w = patchFinding(t, s, fx.high.ID, map[string]any{"fields": map[string]string{"title": "SQLi in login"}},
		map[string]string{uiPreferHeader: uiPreferFull})
	full := decodeUIJSON[map[string]any](t, w, http.StatusOK)
	if _, ok := full["workflow"]; !ok || full["title"] != "SQLi in login" || full["fields"] == nil {
		t.Fatalf("representation = %v", full)
	}
}

func TestUIFindingPatchValidation(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fx := seedUIFindingFixture(t, s)
	cases := []struct {
		fields map[string]string
		field  string
	}{
		{map[string]string{"status": "triaged"}, "status"},
		{map[string]string{"reachability": "reachable"}, "reachability"},
		{map[string]string{"severity": "Huge"}, "severity"},
		{map[string]string{"resolution": "ignore"}, "resolution"},
		{map[string]string{"exploited_in_wild": "maybe"}, "exploited_in_wild"},
		{map[string]string{"ghsa_id": "GHSA-nope"}, "ghsa_id"},
	}
	for _, tc := range cases {
		w := patchFinding(t, s, fx.high.ID, map[string]any{"fields": tc.fields}, nil)
		body := requireUIError(t, w, http.StatusUnprocessableEntity, uiCodeValidationFailed)
		if body.Fields[tc.field] == "" {
			t.Errorf("%v: fields = %v", tc.fields, body.Fields)
		}
	}
	requireUIError(t, patchFinding(t, s, fx.high.ID, map[string]any{"by": "x"}, nil), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, patchFinding(t, s, fx.high.ID, "not json", nil), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, patchFinding(t, s, 9999, map[string]any{"fields": map[string]string{"title": "x"}}, nil), http.StatusNotFound, uiCodeNotFound)
	var f db.Finding
	s.DB.First(&f, fx.high.ID)
	if f.Severity != "High" || f.Status != db.FindingNew {
		t.Fatalf("rejected PATCH wrote: %+v", f)
	}
}

func TestUIFindingPatchConflicts(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fx := seedUIFindingFixture(t, s)
	id := fx.high.ID

	// previous mismatch → 409 with the current row.
	w := patchFinding(t, s, id, map[string]any{"fields": map[string]string{"assignee": "a"}, "previous": map[string]string{"assignee": "someone"}}, nil)
	body := requireUIError(t, w, http.StatusConflict, uiCodeConflict)
	if body.Current == nil || body.Fields["assignee"] == "" || w.Header().Get("ETag") == "" {
		t.Fatalf("conflict body = %+v", body)
	}

	// A client loads (ETag v0), then saves twice in a row with the fresh ETag
	// each time: never a conflict.
	load := serveUI(t, s, operatorReq(t, http.MethodGet, findingPath(id, ""), nil))
	v0 := load.Header().Get("ETag")
	w = patchFinding(t, s, id, map[string]any{"fields": map[string]string{"assignee": "a"}, "previous": map[string]string{"assignee": ""}},
		map[string]string{"If-Match": v0})
	decodeUIJSON[map[string]any](t, w, http.StatusOK)
	v1 := w.Header().Get("ETag")
	w = patchFinding(t, s, id, map[string]any{"fields": map[string]string{"assignee": "ab"}}, map[string]string{"If-Match": v1})
	decodeUIJSON[map[string]any](t, w, http.StatusOK)

	// Someone else edits the assignee after v0 (well past the grace window).
	later := time.Now().Add(2 * uiIfMatchGrace)
	s.DB.Create(&db.FindingHistory{FindingID: id, Field: "assignee", OldValue: "ab", NewValue: "other", Source: db.SourceAnalyst, CreatedAt: later})
	s.DB.Model(&db.Finding{}).Where("id = ?", id).Update("assignee", "other")
	w = patchFinding(t, s, id, map[string]any{"fields": map[string]string{"assignee": "mine"}}, map[string]string{"If-Match": v1})
	requireUIError(t, w, http.StatusConflict, uiCodeConflict)

	// A stale If-Match does not block a field nobody else touched (worker
	// writes bump updated_at all the time).
	w = patchFinding(t, s, id, map[string]any{"fields": map[string]string{"fix_version": "1.2.3"}}, map[string]string{"If-Match": v0})
	decodeUIJSON[map[string]any](t, w, http.StatusOK)

	// If-Match: * is last-write-wins.
	w = patchFinding(t, s, id, map[string]any{"fields": map[string]string{"assignee": "mine"}}, map[string]string{"If-Match": "*"})
	decodeUIJSON[map[string]any](t, w, http.StatusOK)
}

func TestUIFindingNotesCommunicationsReferencesReviews(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fx := seedUIFindingFixture(t, s)
	id := fx.high.ID
	events := captureUIEvents(t, s, uiFindingEvent)
	post := func(suffix string, body any) *httptest.ResponseRecorder {
		return serveUI(t, s, operatorReq(t, http.MethodPost, findingPath(id, suffix), body))
	}
	expectEvent := func(field string) {
		t.Helper()
		evs := events()
		if len(evs) != 1 || strings.Join(eventFields(t, evs[0]), ",") != field || evs[0].RepoID != fx.repoA.ID || evs[0].FindingID != id {
			t.Fatalf("events after %s = %+v", field, evs)
		}
	}

	note := decodeUIJSON[map[string]any](t, post("/notes", map[string]string{"body": " hello ", "by": "w"}), http.StatusCreated)
	if note["body"] != "hello" || note["by"] != "w" {
		t.Fatalf("note = %v", note)
	}
	expectEvent(uiEventNotes)
	requireUIError(t, post("/notes", map[string]string{"body": "  "}), http.StatusUnprocessableEntity, uiCodeValidationFailed)

	comm := decodeUIJSON[map[string]any](t, post("/communications", map[string]string{
		"channel": "email", "direction": "inbound", "actor": "maint", "body": "thanks", "offered_help": "pr", "at": "2026-10-01",
	}), http.StatusCreated)
	if comm["offered_help"] != "pr" || !strings.HasPrefix(comm["at"].(string), "2026-10-01") {
		t.Fatalf("communication = %v", comm)
	}
	expectEvent(uiEventCommunications)
	body := requireUIError(t, post("/communications", map[string]string{"channel": "fax", "at": "yesterday"}), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	if body.Fields["channel"] == "" || body.Fields["at"] == "" {
		t.Fatalf("fields = %v", body.Fields)
	}

	ref := decodeUIJSON[map[string]any](t, post("/references", map[string]string{"url": "https://github.com/a/b/issues/1", "tags": "issue"}), http.StatusCreated)
	if ref["tags"] != "issue" {
		t.Fatalf("reference = %v", ref)
	}
	expectEvent(uiEventReferences)
	requireUIError(t, post("/references", map[string]string{"url": "javascript:alert(1)"}), http.StatusUnprocessableEntity, uiCodeValidationFailed)

	rv := decodeUIJSON[map[string]any](t, post("/reviews", map[string]string{"verdict": "uncertain", "reviewer": "w"}), http.StatusCreated)
	if rv["verdict"] != "uncertain" || rv["agreed"] != nil {
		t.Fatalf("review = %v", rv)
	}
	expectEvent(uiEventReviews)
	requireUIError(t, post("/reviews", map[string]string{"verdict": "false_positive"}), http.StatusUnprocessableEntity, uiCodeValidationFailed)

	for _, suffix := range []string{"/notes", "/communications", "/references", "/reviews"} {
		requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, findingPath(9999, suffix), map[string]string{"body": "x"})),
			http.StatusNotFound, uiCodeNotFound)
	}
	if evs := events(); len(evs) != 0 {
		t.Fatalf("failed writes published %d events", len(evs))
	}
}

func TestUIFindingLabelsPut(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fx := seedUIFindingFixture(t, s)
	if err := db.SeedDefaultLabels(s.DB); err != nil {
		t.Fatal(err)
	}
	events := captureUIEvents(t, s, uiFindingEvent, uiMetaEvent)
	put := func(body any) *httptest.ResponseRecorder {
		return serveUI(t, s, operatorReq(t, http.MethodPut, findingPath(fx.high.ID, "/labels"), body))
	}

	labels := decodeUIJSON[[]map[string]any](t, put(map[string]any{"labels": []string{"wontfix", " brand-new ", ""}}), http.StatusOK)
	if len(labels) != 2 || labels[0]["name"] != "brand-new" || labels[1]["color"] != "#6b7280" {
		t.Fatalf("labels = %v", labels)
	}
	evs := events()
	if len(evs) != 2 || evs[0].Name != uiFindingEvent || evs[1].Name != uiMetaEvent {
		t.Fatalf("events = %+v", evs)
	}

	// Existing names only: no meta event.
	decodeUIJSON[[]map[string]any](t, put(map[string]any{"labels": []string{"wontfix"}}), http.StatusOK)
	if evs := events(); len(evs) != 1 || evs[0].Name != uiFindingEvent {
		t.Fatalf("events = %+v", evs)
	}

	requireUIError(t, put(map[string]any{}), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, put(map[string]any{"labels": []string{strings.Repeat("x", uiLabelNameMax+1)}}), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPut, findingPath(9999, "/labels"), map[string]any{"labels": []string{}})),
		http.StatusNotFound, uiCodeNotFound)
}

func TestUIFindingCampaignPatch(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fx := seedUIFindingFixture(t, s)
	dep := db.Dependent{RepositoryID: fx.repoA.ID, Name: "user"}
	s.DB.Create(&dep)
	s.DB.Create(&db.FindingDependent{FindingID: fx.high.ID, DependentID: dep.ID, Status: db.ExposureKnownAffected})
	path := func(fid, did uint) string { return findingPath(fid, fmt.Sprintf("/dependents/%d/campaign", did)) }
	status := string(db.DependentCampaignStatuses[1])

	row := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodPatch, path(fx.high.ID, dep.ID),
		map[string]string{"status": status, "note": "emailed"})), http.StatusOK)
	if row["status"] != status || row["note"] != "emailed" || row["updated_at"] == nil {
		t.Fatalf("campaign = %v", row)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPatch, path(fx.high.ID, dep.ID), map[string]string{"status": "bogus"})),
		http.StatusUnprocessableEntity, uiCodeValidationFailed)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPatch, path(fx.low.ID, dep.ID), map[string]string{"status": status})),
		http.StatusNotFound, uiCodeNotFound)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPatch, path(9999, dep.ID), map[string]string{"status": status})),
		http.StatusNotFound, uiCodeNotFound)
}
