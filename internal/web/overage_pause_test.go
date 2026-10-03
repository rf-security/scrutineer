package web

import (
	"net/http"
	"net/http/httptest"
	"scrutineer/internal/db"
	"scrutineer/internal/worker"
	"strings"
	"testing"
)

func TestOveragePauseBannerAfterRestart(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker = &worker.Worker{DB: s.DB, Log: s.Log, DataDir: t.TempDir(), PauseOnOverage: true, DowngradeOnOverage: true}
	repo := db.Repository{URL: "https://example.com/overage", Name: "overage"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanPaused, Error: worker.OveragePauseReason}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	s.Worker.Register(s.Queue)
	for _, tc := range []struct {
		path, banner string
	}{
		{"/scans", `<div class="alert-warning mb-6" role="status">
    <i data-lucide="pause"></i>
    <section>
      <strong>Subscription overage.</strong>
      Model scans are paused. Scans resume after a reliable reset; otherwise operator action is required.
    </section>
  </div>`},
		{"/usage", "Subscription overage: model scans are paused"},
	} {
		result := httptest.NewRecorder()
		s.Handler().ServeHTTP(result, localReq(http.MethodGet, tc.path))
		if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), tc.banner) {
			t.Fatalf("%s missing pause banner: status=%d", tc.path, result.Code)
		}
		if strings.Contains(result.Body.String(), "Model fallback active.") {
			t.Fatal("downgrade banner displayed while paused")
		}
	}
}
