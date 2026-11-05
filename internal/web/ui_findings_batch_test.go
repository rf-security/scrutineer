package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

// Tests for POST /ui/findings/batch and the label catalogue routes.

type uiBatchBody struct {
	Results []uiBatchItem `json:"results"`
	Updated int           `json:"updated"`
	Failed  int           `json:"failed"`
}

func postBatch(t *testing.T, s *Server, body any) *httptest.ResponseRecorder {
	t.Helper()
	return serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/findings/batch", body))
}

func TestUIFindingBatchFieldsAndLabels(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fx := seedUIFindingFixture(t, s)
	if err := db.SetFindingLabels(s.DB, fx.low.ID, []string{"keep", "drop"}, db.SourceAnalyst, ""); err != nil {
		t.Fatal(err)
	}
	events := captureUIEvents(t, s, uiFindingEvent, uiMetaEvent)

	res := decodeUIJSON[uiBatchBody](t, postBatch(t, s, map[string]any{
		"ids":    []uint{fx.high.ID, fx.low.ID, 9999},
		"set":    map[string]string{"severity": "Critical", "assignee": "w"},
		"labels": map[string][]string{"add": {"batch-new"}, "remove": {"drop"}},
		"by":     "w",
	}), http.StatusOK)
	if res.Updated != 2 || res.Failed != 1 || len(res.Results) != 3 {
		t.Fatalf("batch = %+v", res)
	}
	if res.Results[2].OK || res.Results[2].Code != uiCodeNotFound {
		t.Fatalf("missing id result = %+v", res.Results[2])
	}
	var high, low db.Finding
	s.DB.Preload("Labels").First(&high, fx.high.ID)
	s.DB.Preload("Labels").First(&low, fx.low.ID)
	if high.Severity != "Critical" || low.Assignee != "w" {
		t.Fatalf("fields not written: %+v %+v", high.Severity, low.Assignee)
	}
	names := []string{}
	for _, l := range sortedLabels(low.Labels) {
		names = append(names, l.Name)
	}
	if strings.Join(names, ",") != "batch-new,keep" {
		t.Fatalf("labels = %v", names)
	}
	evs := events()
	findingEvents, metaEvents := 0, 0
	for _, e := range evs {
		switch e.Name {
		case uiFindingEvent:
			findingEvents++
			if got := strings.Join(eventFields(t, e), ","); got != "assignee,severity,labels" {
				t.Errorf("event fields = %s", got)
			}
		case uiMetaEvent:
			metaEvents++
		}
	}
	if findingEvents != 2 || metaEvents != 1 {
		t.Fatalf("events: %d finding, %d meta", findingEvents, metaEvents)
	}
}

func TestUIFindingBatchStatus(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fx := seedUIFindingFixture(t, s)
	s.DB.Model(&fx.low).Update("disclosure_draft", "ready to go")

	res := decodeUIJSON[uiBatchBody](t, postBatch(t, s, map[string]any{
		"ids": []uint{fx.high.ID, fx.low.ID}, "set": map[string]string{"status": "ready"},
	}), http.StatusOK)
	if res.Updated != 1 || res.Results[0].Code != uiCodeValidationFailed || !res.Results[1].OK {
		t.Fatalf("ready batch = %+v", res)
	}

	s.DB.Model(&fx.other).Update("production_viability", db.ProductionViabilityNonViable)
	res = decodeUIJSON[uiBatchBody](t, postBatch(t, s, map[string]any{
		"ids": []uint{fx.other.ID}, "set": map[string]string{"status": "reported"},
	}), http.StatusOK)
	if res.Failed != 1 || res.Results[0].Code != uiCodePreconditionFailed {
		t.Fatalf("non-viable batch = %+v", res)
	}

	// Rejected goes through RejectFinding: verdict and reason required.
	res = decodeUIJSON[uiBatchBody](t, postBatch(t, s, map[string]any{
		"ids": []uint{fx.high.ID}, "set": map[string]string{"status": "rejected"},
	}), http.StatusOK)
	if res.Results[0].Code != uiCodeValidationFailed {
		t.Fatalf("rejected without reason = %+v", res)
	}
	res = decodeUIJSON[uiBatchBody](t, postBatch(t, s, map[string]any{
		"ids": []uint{fx.high.ID}, "set": map[string]string{"status": "rejected"},
		"verdict": "false_positive", "reason": "test fixture", "reviewer": "w",
	}), http.StatusOK)
	if !res.Results[0].OK {
		t.Fatalf("rejected = %+v", res)
	}
	var high db.Finding
	s.DB.First(&high, fx.high.ID)
	var reviews int64
	s.DB.Model(&db.FindingReview{}).Where("finding_id = ?", fx.high.ID).Count(&reviews)
	if high.Status != db.FindingRejected || reviews != 1 {
		t.Fatalf("status %s, reviews %d", high.Status, reviews)
	}
}

func TestUIFindingBatchValidation(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	tooMany := make([]uint, uiBatchMaxIDs+1)
	for i := range tooMany {
		tooMany[i] = uint(i + 1)
	}
	cases := []struct {
		body  any
		field string
	}{
		{map[string]any{"ids": []uint{}, "set": map[string]string{"assignee": "x"}}, "ids"},
		{map[string]any{"ids": tooMany, "set": map[string]string{"assignee": "x"}}, "ids"},
		{map[string]any{"ids": []uint{1}}, "set"},
		{map[string]any{"ids": []uint{1}, "set": map[string]string{"title": "x"}}, "set.title"},
		{map[string]any{"ids": []uint{1}, "set": map[string]string{"status": "open"}}, "set.status"},
		{map[string]any{"ids": []uint{1}, "set": map[string]string{"severity": "huge"}}, "set.severity"},
	}
	for _, tc := range cases {
		body := requireUIError(t, postBatch(t, s, tc.body), http.StatusUnprocessableEntity, uiCodeValidationFailed)
		if body.Fields[tc.field] == "" {
			t.Errorf("%v: fields = %v", tc.body, body.Fields)
		}
	}
	requireUIError(t, postBatch(t, s, "nope"), http.StatusBadRequest, uiCodeBadParam)
}

func TestUILabelCRUD(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fx := seedUIFindingFixture(t, s)
	events := captureUIEvents(t, s, uiMetaEvent)
	labelPath := func(id any) string { return fmt.Sprintf("/api/v1/ui/labels/%v", id) }

	created := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/labels",
		map[string]string{"name": " triage-me ", "color": "#aabbcc"})), http.StatusCreated)
	id := uint(created["id"].(float64))
	if created["name"] != "triage-me" || created["finding_count"].(float64) != 0 {
		t.Fatalf("created = %v", created)
	}
	if evs := events(); len(evs) != 1 {
		t.Fatalf("meta events = %d", len(evs))
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/labels", map[string]string{"name": "triage-me"})),
		http.StatusConflict, uiCodeConflict)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/labels", map[string]string{"name": "x", "color": "red"})),
		http.StatusUnprocessableEntity, uiCodeValidationFailed)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/labels", map[string]string{"color": "#000000"})),
		http.StatusUnprocessableEntity, uiCodeValidationFailed)

	if err := db.SetFindingLabels(s.DB, fx.high.ID, []string{"triage-me", "other"}, db.SourceAnalyst, ""); err != nil {
		t.Fatal(err)
	}
	list := decodeUIJSON[[]map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/labels", nil)), http.StatusOK)
	if len(list) != 2 || list[1]["name"] != "triage-me" || list[1]["finding_count"].(float64) != 1 {
		t.Fatalf("list = %v", list)
	}

	patched := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodPatch, labelPath(id),
		map[string]string{"name": "triaged-later"})), http.StatusOK)
	if patched["name"] != "triaged-later" || patched["color"] != "#aabbcc" || patched["finding_count"].(float64) != 1 {
		t.Fatalf("patched = %v", patched)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPatch, labelPath(id), map[string]string{"name": "other"})),
		http.StatusConflict, uiCodeConflict)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPatch, labelPath(id), map[string]string{"color": "#12"})),
		http.StatusUnprocessableEntity, uiCodeValidationFailed)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPatch, labelPath(9999), map[string]string{"color": "#123456"})),
		http.StatusNotFound, uiCodeNotFound)

	if w := serveUI(t, s, operatorReq(t, http.MethodDelete, labelPath(id), nil)); w.Code != http.StatusNoContent {
		t.Fatalf("delete = %d %s", w.Code, w.Body.String())
	}
	var joins int64
	s.DB.Table(uiLabelJoinTable).Where("finding_label_id = ?", id).Count(&joins)
	if joins != 0 {
		t.Fatalf("join rows left: %d", joins)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodDelete, labelPath(id), nil)), http.StatusNotFound, uiCodeNotFound)
	if evs := events(); len(evs) != 2 {
		t.Fatalf("meta events after patch+delete = %d", len(evs))
	}
}
