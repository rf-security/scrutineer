package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func seedObservedFinding(t *testing.T, s *Server) db.Finding {
	t.Helper()
	repo := db.Repository{URL: "https://github.com/example/obs", Name: "obs"}
	s.DB.Create(&repo)
	scan1 := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive", Backend: "claude-code", Model: "model-a", Commit: "abcdef1234567890", APIToken: "tok-obs"}
	scan2 := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive", Backend: "codex", Model: "model-b", Commit: "123456abcdef7890"}
	s.DB.Create(&scan1)
	s.DB.Create(&scan2)
	f := db.Finding{ScanID: scan1.ID, RepositoryID: repo.ID, Title: "SQLi", Severity: "High", Status: db.FindingNew}
	s.DB.Create(&f)
	for _, o := range []db.FindingObservation{
		{FindingID: f.ID, ScanID: scan1.ID, RepositoryID: repo.ID, SkillName: "security-deep-dive", Backend: "claude-code", Model: "model-a", Commit: scan1.Commit, Title: "SQLi", Severity: "High", Reachability: "reachable", Evidence: `{"trace":"first trace"}`},
		{FindingID: f.ID, ScanID: scan2.ID, RepositoryID: repo.ID, SkillName: "security-deep-dive", Backend: "codex", Model: "model-b", Commit: scan2.Commit, Title: "<script>alert(1)</script>", Severity: "Low", Reachability: "harness_only", Evidence: `{"trace":"<b>second trace</b>"}`},
	} {
		if err := db.RecordFindingObservation(s.DB, o); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func TestFindingShowListsObservationsWithDisagreementNotice(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedObservedFinding(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d", f.ID)))
	if w.Code != http.StatusOK {
		t.Fatalf("GET status = %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{"Observations", "model-a", "model-b", "codex", "disagree on severity, reachability", "first trace"} {
		if !strings.Contains(body, want) {
			t.Errorf("finding page missing %q", want)
		}
	}
	if strings.Contains(body, "<script>alert(1)</script>") || strings.Contains(body, "<b>second trace</b>") {
		t.Error("observation content was not escaped")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("escaped observation title missing")
	}
}

func TestFindingShowHidesObservationsWhenNone(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedFindingForForm(t, s)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d", f.ID)))
	if strings.Contains(w.Body.String(), "Agreement between scans is not verification") {
		t.Error("observations section rendered with no observations")
	}
}

func TestAPIListFindingObservations(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedObservedFinding(t, s)
	s.DB.Model(&db.Scan{}).Where("api_token = ?", "tok-obs").Update("status", db.ScanRunning)

	r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/findings/%d/observations", f.ID), nil)
	asOperator(r)
	r.Header.Set("Authorization", "Bearer tok-obs")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	var got []map[string]any
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0]["model"] != "model-a" || got[1]["severity"] != "Low" {
		t.Fatalf("observations = %+v", got)
	}
	if ev, ok := got[0]["evidence"].(map[string]any); !ok || ev["trace"] != "first trace" {
		t.Errorf("evidence not decoded: %+v", got[0]["evidence"])
	}

	r = httptest.NewRequest(http.MethodGet, "/api/findings/99999/observations", nil)
	asOperator(r)
	r.Header.Set("Authorization", "Bearer tok-obs")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown finding status = %d, want 404", w.Code)
	}
}

func TestFindingShowCapsObservationsAtNewest(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/example/obs-cap", Name: "obs-cap"}
	s.DB.Create(&repo)
	origin := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone}
	s.DB.Create(&origin)
	f := db.Finding{ScanID: origin.ID, RepositoryID: repo.ID, Title: "busy", Severity: "High", Status: db.FindingNew}
	if err := s.DB.Create(&f).Error; err != nil {
		t.Fatal(err)
	}
	n := maxPageObservations + 5
	for i := 1; i <= n; i++ {
		scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, Model: fmt.Sprintf("model-%02d", i)}
		s.DB.Create(&scan)
		if err := db.RecordFindingObservation(s.DB, db.ObservationFromFinding(&scan, &db.Finding{ID: f.ID, Title: "busy"})); err != nil {
			t.Fatal(err)
		}
	}

	view, err := loadFindingObservationViews(s.DB, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Rows) != maxPageObservations || view.Total != int64(n) {
		t.Fatalf("rows = %d total = %d, want %d of %d", len(view.Rows), view.Total, maxPageObservations, n)
	}
	if first, last := view.Rows[0].Model, view.Rows[len(view.Rows)-1].Model; first != "model-06" || last != fmt.Sprintf("model-%02d", n) {
		t.Errorf("page rows run %s..%s, want the newest oldest first", first, last)
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d", f.ID)))
	if body := w.Body.String(); !strings.Contains(body, fmt.Sprintf("Showing the newest %d of %d", maxPageObservations, n)) {
		t.Error("finding page missing the truncation note")
	}

	rows, total, err := db.FindingContributions(s.DB, f.ID, 0)
	if err != nil || len(rows) != n || total != int64(n) {
		t.Fatalf("unlimited contributions = %d rows total %d err %v, want %d", len(rows), total, err, n)
	}
}

func TestFindingShowReportsDisagreementBeyondPageCap(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/example/obs-old-disagree", Name: "obs-old-disagree"}
	s.DB.Create(&repo)
	origin := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone}
	s.DB.Create(&origin)
	f := db.Finding{ScanID: origin.ID, RepositoryID: repo.ID, Title: "drift", Severity: "Low", Status: db.FindingNew}
	if err := s.DB.Create(&f).Error; err != nil {
		t.Fatal(err)
	}
	n := maxPageObservations + 5
	for i := 1; i <= n; i++ {
		severity := "Low"
		if i <= n-maxPageObservations {
			severity = "High"
		}
		scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone}
		s.DB.Create(&scan)
		if err := db.RecordFindingObservation(s.DB, db.ObservationFromFinding(&scan, &db.Finding{ID: f.ID, Title: "drift", Severity: severity})); err != nil {
			t.Fatal(err)
		}
	}

	view, err := loadFindingObservationViews(s.DB, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range view.Rows {
		if row.Severity != "Low" {
			t.Fatalf("page row severity = %q, want only the newest Low rows shown", row.Severity)
		}
	}
	if !slices.Equal(view.Disagreements, []string{"severity"}) {
		t.Errorf("disagreements = %v, want [severity] from the older hidden rows", view.Disagreements)
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d", f.ID)))
	if !strings.Contains(w.Body.String(), "disagree on severity") {
		t.Error("finding page missing the disagreement notice for hidden rows")
	}
}
