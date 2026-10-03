package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func repositoryAuditEvents(t *testing.T, s *Server) []db.AuditEvent {
	t.Helper()
	var events []db.AuditEvent
	if err := s.DB.Where("subject_type = ?", db.AuditSubjectRepository).Order("id").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	return events
}

func assertRepositoryAuditEvent(t *testing.T, event db.AuditEvent, kind string, repo db.Repository) {
	t.Helper()
	if event.Kind != kind || event.SubjectID != repo.ID || event.SubjectType != db.AuditSubjectRepository || event.Source != db.SourceAnalyst || event.Actor != "" {
		t.Fatalf("event = %+v", event)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal([]byte(event.Payload), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload) != 3 {
		t.Fatalf("unexpected payload fields: %s", event.Payload)
	}
	for key, value := range map[string]any{"repository_id": repo.ID, "name": repo.Name, "full_name": repo.FullName} {
		want, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if string(payload[key]) != string(want) {
			t.Fatalf("payload %s = %s, want %s", key, payload[key], want)
		}
	}
}

func TestRepositoryAuditCreateHandlers(t *testing.T) {
	for _, bulk := range []bool{false, true} {
		t.Run(fmt.Sprintf("bulk=%t", bulk), func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			path := "/repositories"
			form := url.Values{"url": {"https://github.com/acme/widget"}, "actor": {"untrusted"}}
			if bulk {
				path += "/bulk"
				form = url.Values{"urls": {"https://github.com/acme/widget\nhttps://github.com/acme/widget\ninvalid"}}
			}
			for range 2 {
				w := postForm(t, s, path, form)
				if w.Code != http.StatusSeeOther {
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

func TestRepositoryAuditConcurrentCreate(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	const callers = 6
	start := make(chan struct{})
	results := make(chan bool, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			<-start
			_, created, err := s.createOrTriageRepo(context.Background(), RepoInput{
				CloneURL: "https://github.com/acme/widget", Name: "widget", Owner: "acme",
			}, "", false)
			results <- created
			errs <- err
		})
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var created int
	for isNew := range results {
		if isNew {
			created++
		}
	}
	if created != 1 || len(repositoryAuditEvents(t, s)) != 1 {
		t.Fatalf("created = %d, want one row and event", created)
	}
}

func TestRepositoryAuditExistingRepository(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/acme/widget", Name: "canonical", FullName: "acme/canonical", ScanConfig: "operator configuration"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	failFindingAuditInsert(t, s)
	got, created, err := s.createOrTriageRepo(context.Background(), RepoInput{
		CloneURL: repo.URL, Name: "submitted", Owner: "different",
	}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if created || got.ID != repo.ID || got.Name != repo.Name || got.FullName != repo.FullName || got.ScanConfig != repo.ScanConfig {
		t.Fatalf("existing repository changed: created=%t, repo=%+v", created, got)
	}
	if len(repositoryAuditEvents(t, s)) != 0 {
		t.Fatal("existing repository produced an event")
	}
}

func TestRepositoryAuditCreateRollback(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	failFindingAuditInsert(t, s)
	prefetched := false
	s.prefetchEcosystems = func(uint) { prefetched = true }
	if err := s.DB.Create(&db.Skill{Name: defaultSkillName, Active: true}).Error; err != nil {
		t.Fatal(err)
	}
	w := postForm(t, s, "/repositories", url.Values{"url": {"https://github.com/acme/widget"}})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	for _, model := range []any{&db.Repository{}, &db.Scan{}, &db.AuditEvent{}} {
		var count int64
		if err := s.DB.Model(model).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%T rows after rollback = %d", model, count)
		}
	}
	if prefetched {
		t.Fatal("prefetch started before creation committed")
	}
}

func deleteRepositoryRequest(t *testing.T, s *Server, id uint, api bool) *httptest.ResponseRecorder {
	t.Helper()
	method, path := http.MethodPost, fmt.Sprintf("/repositories/%d/delete", id)
	if api {
		method, path = http.MethodDelete, fmt.Sprintf("/api/v1/repositories/%d", id)
	}
	r := localReq(method, path)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestRepositoryAuditDeleteHandlers(t *testing.T) {
	for _, api := range []bool{false, true} {
		t.Run(fmt.Sprintf("api=%t", api), func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			s.Worker.DataDir = t.TempDir()
			repo := db.Repository{URL: "https://user:secret@example.com/widget?token=secret", Name: "widget", FullName: "acme/widget", ScanConfig: "secret-config", Metadata: "secret-metadata"}
			if _, err := s.createRepositoryWithAudit(context.Background(), &repo); err != nil {
				t.Fatal(err)
			}
			w := deleteRepositoryRequest(t, s, repo.ID, api)
			want := http.StatusSeeOther
			if api {
				want = http.StatusNoContent
			}
			if w.Code != want {
				t.Fatalf("status = %d: %s", w.Code, w.Body)
			}
			var got db.Repository
			if err := s.DB.First(&got, repo.ID).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
				t.Fatalf("repository survived deletion: %v", err)
			}
			events := repositoryAuditEvents(t, s)
			if len(events) != 2 {
				t.Fatalf("events = %+v", events)
			}
			assertRepositoryAuditEvent(t, events[0], db.AuditEventRepositoryCreated, repo)
			assertRepositoryAuditEvent(t, events[1], db.AuditEventRepositoryDeleted, repo)
			if _, err := s.deleteRepository(repo); !errors.Is(err, gorm.ErrRecordNotFound) {
				t.Fatalf("stale deletion error = %v", err)
			}
			if w := deleteRepositoryRequest(t, s, repo.ID, api); w.Code != http.StatusNotFound {
				t.Fatalf("repeat status = %d", w.Code)
			}
			if len(repositoryAuditEvents(t, s)) != 2 {
				t.Fatal("duplicate deletion event")
			}
		})
	}
}

func repositoryAuditCacheMarker(t *testing.T, s *Server, repo db.Repository) string {
	t.Helper()
	cache := worker.RepoCacheRoot(s.Worker.DataDir, repo.URL)
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(cache, "keep")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	return marker
}

func TestRepositoryAuditDeleteRollback(t *testing.T) {
	for _, api := range []bool{false, true} {
		t.Run(fmt.Sprintf("api=%t", api), func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			s.Worker.DataDir = t.TempDir()
			repo := db.Repository{URL: "https://github.com/acme/widget", Name: "widget"}
			if _, err := s.createRepositoryWithAudit(context.Background(), &repo); err != nil {
				t.Fatal(err)
			}
			scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone}
			if err := s.DB.Create(&scan).Error; err != nil {
				t.Fatal(err)
			}
			marker := repositoryAuditCacheMarker(t, s, repo)
			failFindingAuditInsert(t, s)
			w := deleteRepositoryRequest(t, s, repo.ID, api)
			want := http.StatusSeeOther
			if api {
				want = http.StatusInternalServerError
			}
			if w.Code != want {
				t.Fatalf("status = %d: %s", w.Code, w.Body)
			}
			if err := s.DB.First(&repo, repo.ID).Error; err != nil {
				t.Fatal(err)
			}
			if err := s.DB.First(&scan, scan.ID).Error; err != nil {
				t.Fatalf("child deletion was not rolled back: %v", err)
			}
			if _, err := os.Stat(marker); err != nil {
				t.Fatalf("artifact removed on rollback: %v", err)
			}
			if events := repositoryAuditEvents(t, s); len(events) != 1 || events[0].Kind != db.AuditEventRepositoryCreated {
				t.Fatalf("events after rollback = %+v", events)
			}
		})
	}
}

func TestRepositoryAuditDeleteInFlight(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/acme/widget", Name: "widget"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&db.Scan{RepositoryID: repo.ID, Status: db.ScanRunning}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := s.deleteRepository(repo); !errors.Is(err, errRepositoryDeleteInFlight) {
		t.Fatalf("error = %v", err)
	}
	if len(repositoryAuditEvents(t, s)) != 0 {
		t.Fatal("rejected deletion created an event")
	}
}
