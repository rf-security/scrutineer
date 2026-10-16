package web

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestScanShowDisplaysScopeAndProfile(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/mixed", Name: "mixed"}
	s.DB.Create(&repo)
	for _, tt := range []struct {
		name, subpath, profile, focus, wantProfile string
		status                                     db.ScanStatus
	}{
		{"finished focus", "packages/client", "node", `{"name":"Action handlers","paths":["packages/client/src/**"],"surface":"Redux actions"}`, "node", db.ScanDone},
		{"queued automatic", "", "", "", "Automatic", db.ScanQueued},
		{"queued override", "Classes", "php", "", "php", db.ScanQueued},
		{"default override", "", "default", "", "default", db.ScanQueued},
		{"unrecorded", "", "", "", "Not recorded", db.ScanDone},
		{"malformed legacy focus", "", "", "broken", "Not recorded", db.ScanDone},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: deepDiveSkillName, Status: tt.status,
				SubPath: tt.subpath, Profile: tt.profile, FocusArea: tt.focus, ScanGroup: "focus-42"}
			if err := s.DB.Create(&scan).Error; err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/scans/%d", scan.ID)))
			if w.Code != 200 {
				t.Fatalf("status = %d: %s", w.Code, w.Body)
			}
			body := w.Body.String()
			path := tt.subpath
			if path == "" {
				path = "root"
			}
			for _, want := range []string{"Subpath", "<code>" + path + "</code>", "Runner profile", "<dd>" + tt.wantProfile + "</dd>"} {
				if !strings.Contains(body, want) {
					t.Errorf("missing %q", want)
				}
			}
			if tt.name == "finished focus" {
				for _, want := range []string{"Action handlers", "packages/client/src/**", "Redux actions", `href="/scans?group=focus-42"`} {
					if !strings.Contains(body, want) {
						t.Errorf("missing %q", want)
					}
				}
			}
		})
	}
}

func TestRepoScanRowsDisplaySubpathsOnRefresh(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/mixed", Name: "mixed"}
	s.DB.Create(&repo)
	for _, subpath := range []string{"packages/client", "Classes"} {
		if err := s.DB.Create(&db.Scan{RepositoryID: repo.ID, SkillName: deepDiveSkillName, Status: db.ScanRunning, SubPath: subpath}).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{fmt.Sprintf("/repositories/%d", repo.ID), fmt.Sprintf("/repositories/%d/scans", repo.ID)} {
		w := httptest.NewRecorder()
		r := localReq("GET", path)
		r.Header.Set("HX-Request", "true")
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: status %d: %s", path, w.Code, w.Body)
		}
		body := w.Body.String()
		for _, want := range []string{"Subpath: <code>packages/client</code>", "Subpath: <code>Classes</code>"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s missing %q", path, want)
			}
		}
	}
}
