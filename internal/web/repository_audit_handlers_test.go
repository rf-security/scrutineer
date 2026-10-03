package web

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

func TestRepositoryAuditImport(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		t.Run(fmt.Sprintf("fallback=%t", fallback), func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			body, status := repositoryAuditImportBody(t, s, fallback)
			for range 2 {
				w := postImport(t, s, "/api/v1/import?repo=https://github.com/acme/widget&revalidate=false", body)
				if w.Code != status {
					t.Fatalf("status = %d: %s", w.Code, w.Body)
				}
			}
			var repo db.Repository
			if err := s.DB.First(&repo).Error; err != nil {
				t.Fatal(err)
			}
			events := repositoryAuditEvents(t, s)
			if len(events) != 1 {
				t.Fatalf("events = %+v", events)
			}
			assertRepositoryAuditEvent(t, events[0], db.AuditEventRepositoryCreated, repo)
		})
	}
}

func repositoryAuditImportBody(t *testing.T, s *Server, fallback bool) (string, int) {
	t.Helper()
	if !fallback {
		return `{"findings":[{"title":"imported finding","severity":"High","location":"main.go:1"}]}`, http.StatusCreated
	}
	if err := s.DB.Create(&db.Skill{Name: ingestSkillName, Active: true, Version: 1, OutputFile: "report.json", OutputKind: "findings"}).Error; err != nil {
		t.Fatal(err)
	}
	return "unrecognised report for the ingest skill", http.StatusAccepted
}

func TestRepositoryAuditImportEventFailure(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		t.Run(fmt.Sprintf("fallback=%t", fallback), func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			body, _ := repositoryAuditImportBody(t, s, fallback)
			failFindingAuditInsert(t, s)
			w := postImport(t, s, "/api/v1/import?repo=https://github.com/acme/widget&revalidate=false", body)
			if w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d: %s", w.Code, w.Body)
			}
			for _, model := range []any{&db.Repository{}, &db.Scan{}, &db.Finding{}, &db.AuditEvent{}} {
				var count int64
				if err := s.DB.Model(model).Count(&count).Error; err != nil {
					t.Fatal(err)
				}
				if count != 0 {
					t.Fatalf("%T rows after rollback = %d", model, count)
				}
			}
		})
	}
}

// Delete immediately after the handler's initial read, before the transaction
// re-reads the repository. No timing or concurrent goroutine is required.
func deleteAfterRepositoryLookup(t *testing.T, s *Server, repo db.Repository) {
	t.Helper()
	const callback = "test:delete_after_repository_lookup"
	deleted := false
	if err := s.DB.Callback().Query().After("gorm:after_query").Register(callback, func(tx *gorm.DB) {
		if deleted || tx.Statement.Schema == nil || tx.Statement.Schema.Name != "Repository" || tx.Error != nil {
			return
		}
		deleted = true
		if err := s.DB.Delete(&repo).Error; err != nil {
			_ = tx.AddError(err)
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.DB.Callback().Query().Remove(callback); err != nil {
			t.Error(err)
		}
	})
}

func TestRepositoryAuditConcurrentDeleteResponse(t *testing.T) {
	for _, mode := range []string{"api", "browser", "htmx"} {
		t.Run(mode, func(t *testing.T) {
			testRepositoryAuditConcurrentDeleteResponse(t, mode)
		})
	}
}

func testRepositoryAuditConcurrentDeleteResponse(t *testing.T, mode string) {
	t.Helper()
	s, done := newTestServer(t)
	defer done()
	var logs bytes.Buffer
	s.Log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := db.Repository{URL: "https://github.com/acme/widget", Name: "widget"}
	if _, err := s.createRepositoryWithAudit(context.Background(), &repo); err != nil {
		t.Fatal(err)
	}
	deleteAfterRepositoryLookup(t, s, repo)
	method, path := http.MethodPost, fmt.Sprintf("/repositories/%d/delete", repo.ID)
	if mode == "api" {
		method, path = http.MethodDelete, fmt.Sprintf("/api/v1/repositories/%d", repo.ID)
	}
	r := localReq(method, path)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if mode == "htmx" {
		r.Header.Set("HX-Request", "true")
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	switch mode {
	case "api":
		if w.Code != http.StatusNotFound || !bytes.Contains(w.Body.Bytes(), []byte("repository not found")) {
			t.Fatalf("response = %d: %s", w.Code, w.Body)
		}
	case "browser":
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
			t.Fatalf("response = %d: %v", w.Code, w.Header())
		}
	case "htmx":
		if w.Code != http.StatusNoContent || w.Header().Get("HX-Redirect") != "/" {
			t.Fatalf("response = %d: %v", w.Code, w.Header())
		}
	}
	if mode != "api" && flashFrom(t, w).Title != "Repository not found" {
		t.Fatalf("flash = %+v", flashFrom(t, w))
	}
	if logs.Len() != 0 {
		t.Fatalf("not-found deletion logged an error: %s", &logs)
	}
	if events := repositoryAuditEvents(t, s); len(events) != 1 || events[0].Kind != db.AuditEventRepositoryCreated {
		t.Fatalf("unexpected deletion event: %+v", events)
	}
}
