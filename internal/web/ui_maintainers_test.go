package web

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
)

func TestUIInventoryMaintainerList(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedInventory(t, s)
	s.DB.Create(&db.Maintainer{Login: "bob", Name: "Bob", Status: db.MaintainerInactive})

	list := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/maintainers", nil)))
	if list.Total != 2 || list.Items[0]["login"] != "alice" {
		t.Fatalf("list = %+v", list)
	}
	alice := list.Items[0]
	// finding_count keeps the HTML number (closed included, scanner noise
	// excluded); open_finding_count drops the closed one.
	if alice["repository_count"] != float64(2) || alice["finding_count"] != float64(2) || alice["open_finding_count"] != float64(1) {
		t.Errorf("alice counts = %v", alice)
	}
	if alice["id"] != float64(fx.maintainer.ID) || alice["status"] != "active" || alice["do_not_contact"] != false {
		t.Errorf("alice = %v", alice)
	}

	inactive := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/maintainers?status=inactive", nil)))
	if inactive.Total != 1 || inactive.Items[0]["login"] != "bob" {
		t.Errorf("status=inactive = %+v", inactive)
	}
	sorted := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/maintainers?sort=repos", nil)))
	if sorted.Items[0]["login"] != "alice" {
		t.Errorf("sort=repos first = %v", sorted.Items[0]["login"])
	}
	q := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/maintainers?q=BO&page_size=1", nil)))
	if q.Total != 1 || q.PageSize != 1 || q.Items[0]["login"] != "bob" {
		t.Errorf("q=BO = %+v", q)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/maintainers?status=retired", nil)), http.StatusBadRequest, uiCodeBadParam)
}

func TestUIInventoryMaintainerShowAndTabs(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedInventory(t, s)
	base := fmt.Sprintf("/api/v1/ui/maintainers/%d", fx.maintainer.ID)

	w := serveUI(t, s, operatorReq(t, "GET", base, nil))
	got := decodeUIJSON[map[string]any](t, w, http.StatusOK)
	if got["login"] != "alice" || got["repository_count"] != float64(2) {
		t.Fatalf("detail = %v", got)
	}
	if w.Header().Get("ETag") == "" {
		t.Error("detail without ETag")
	}

	repos := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", base+"/repositories", nil)))
	if repos.Total != 2 || repos.Items[0]["name"] != "alpha" || repos.Items[1]["name"] != "beta" {
		t.Errorf("repositories = %+v", repos)
	}
	findings := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", base+"/findings", nil)))
	if findings.Total != 1 || findings.Items[0]["id"] != float64(fx.open.ID) {
		t.Errorf("findings = %+v, want only the open curated finding", findings)
	}

	for _, path := range []string{"", "/repositories", "/findings"} {
		requireUIError(t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/maintainers/9999"+path, nil)), http.StatusNotFound, uiCodeNotFound)
		requireUIError(t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/maintainers/abc"+path, nil)), http.StatusBadRequest, uiCodeBadParam)
	}
}

func TestUIInventoryMaintainerPatch(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedInventory(t, s)
	path := fmt.Sprintf("/api/v1/ui/maintainers/%d", fx.maintainer.ID)
	etag := serveUI(t, s, operatorReq(t, "GET", path, nil)).Header().Get("ETag")
	time.Sleep(2 * time.Millisecond) // updated_at must move

	req := operatorReq(t, "PATCH", path, map[string]any{"do_not_contact": true})
	req.Header.Set("If-Match", etag)
	w := serveUI(t, s, req)
	got := decodeUIJSON[map[string]any](t, w, http.StatusOK)
	if got["do_not_contact"] != true {
		t.Fatalf("patched = %v", got)
	}
	newTag := w.Header().Get("ETag")
	if newTag == "" || newTag == etag {
		t.Errorf("ETag %q did not change from %q", newTag, etag)
	}
	var m db.Maintainer
	s.DB.First(&m, fx.maintainer.ID)
	if !m.DoNotContact {
		t.Fatal("flag not stored")
	}

	// The old version is now stale.
	stale := operatorReq(t, "PATCH", path, map[string]any{"do_not_contact": false})
	stale.Header.Set("If-Match", etag)
	body := requireUIError(t, serveUI(t, s, stale), http.StatusConflict, uiCodeConflict)
	if body.Current["do_not_contact"] != true {
		t.Errorf("conflict current = %v", body.Current)
	}

	// Last-write-wins without If-Match.
	got = decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, "PATCH", path, map[string]any{"do_not_contact": false})), http.StatusOK)
	if got["do_not_contact"] != false {
		t.Errorf("cleared = %v", got)
	}

	body = requireUIError(t, serveUI(t, s, operatorReq(t, "PATCH", path, map[string]any{})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	if body.Fields["do_not_contact"] == "" {
		t.Errorf("422 fields = %v", body.Fields)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, "PATCH", path, "{not json")), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, serveUI(t, s, operatorReq(t, "PATCH", "/api/v1/ui/maintainers/9999", map[string]any{"do_not_contact": true})),
		http.StatusNotFound, uiCodeNotFound)
}

// The HTML maintainer index keeps its behaviour after the helper extraction.
func TestUIInventoryMaintainerHTMLUnchanged(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedInventory(t, s)
	w := serveUI(t, s, localReq("GET", "/maintainers?status=active&sort=findings"))
	if w.Code != http.StatusOK {
		t.Fatalf("maintainers page = %d", w.Code)
	}
	if want := fmt.Sprintf(`id="maintainer-%d"`, fx.maintainer.ID); !strings.Contains(w.Body.String(), want) {
		t.Errorf("maintainers page missing %s", want)
	}
}
