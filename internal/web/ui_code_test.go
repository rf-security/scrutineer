package web

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

// Tests for the code browser JSON (#54 blob, #55 tree) against a local
// (file://) repository so no clone or network is involved.

func seedUICodeRepo(t *testing.T, s *Server) (db.Repository, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	s.Worker = &worker.Worker{DataDir: t.TempDir()}
	local := t.TempDir()
	if err := os.MkdirAll(filepath.Join(local, "src", "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(local, "src", "deep", "x.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commitBlob(t, local, "main.go", []byte("package main\n\nfunc main() {}\n"))
	cmd := exec.Command("git", "-C", local, "add", "src")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v %s", err, out)
	}
	commitAll := exec.Command("git", "-C", local, "-c", "user.email=t@e", "-c", "user.name=T", "commit", "--quiet", "-m", "src")
	if out, err := commitAll.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v %s", err, out)
	}
	repo := db.Repository{URL: "file://" + local, Name: "local"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	return repo, headCommit(t, local)
}

func TestUIRepoBlob(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, commit := seedUICodeRepo(t, s)
	path := repoPath(repo.ID, "/blob/"+commit+"/main.go?line=3")

	w := serveUI(t, s, operatorReq(t, http.MethodGet, path, nil))
	body := decodeUIJSON[map[string]any](t, w, http.StatusOK)
	if body["content"] != "package main\n\nfunc main() {}\n" || body["language"] != "go" || body["local"] != true ||
		body["size_bytes"] != float64(29) {
		t.Fatalf("blob = %+v", body)
	}
	if hl := body["highlight"].([]any); hl[0] != float64(3) || hl[1] != float64(3) {
		t.Fatalf("highlight = %+v", hl)
	}
	etag := w.Header().Get("ETag")
	if etag != `"`+commit+`:main.go"` || w.Header().Get("Cache-Control") != immutableFor {
		t.Fatalf("cache headers = %q %q", etag, w.Header().Get("Cache-Control"))
	}
	r := operatorReq(t, http.MethodGet, path, nil)
	r.Header.Set("If-None-Match", etag)
	if w = serveUI(t, s, r); w.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match = %d", w.Code)
	}

	short := serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(repo.ID, "/blob/"+commit[:8]+"/main.go"), nil))
	if decodeUIJSON[map[string]any](t, short, http.StatusOK)["content"] == "" || short.Header().Get("Cache-Control") != noStore {
		t.Fatalf("short SHA cache = %q", short.Header().Get("Cache-Control"))
	}
	missingFile := getUI(t, s, repoPath(repo.ID, "/blob/"+commit+"/nope.go"))
	if missingFile["error"] == nil {
		t.Fatalf("missing file = %+v", missingFile)
	}

	remote := seedUIRepo(t, s.DB, "never-cloned")
	if noClone := getUI(t, s, repoPath(remote.ID, "/blob/"+commit+"/main.go")); noClone["missing"] != true {
		t.Fatalf("no clone = %+v", noClone)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(repo.ID, "/blob/XYZ/main.go"), nil)), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(repo.ID, "/blob/"+commit+"/a%00b"), nil)), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(9999, "/blob/"+commit+"/main.go"), nil)), http.StatusNotFound, uiCodeNotFound)
}

func TestUIRepoTree(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, commit := seedUICodeRepo(t, s)

	root := getUI(t, s, repoPath(repo.ID, "/tree/"+commit+"/"))
	entries := root["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("root = %+v", root)
	}
	first, second := entries[0].(map[string]any), entries[1].(map[string]any)
	if first["name"] != "src" || first["type"] != "dir" || first["size"] != nil || second["name"] != "main.go" || second["type"] != "file" {
		t.Fatalf("entries = %+v", entries)
	}
	deep := getUI(t, s, repoPath(repo.ID, "/tree/"+commit+"/src?depth=2"))
	dir := deep["entries"].([]any)[0].(map[string]any)
	if dir["name"] != "deep" || len(dir["entries"].([]any)) != 1 {
		t.Fatalf("depth=2 = %+v", deep)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(repo.ID, "/tree/"+commit+"/main.go"), nil)), http.StatusNotFound, uiCodeNotFound)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(repo.ID, "/tree/"+commit+"/?depth=3"), nil)), http.StatusBadRequest, uiCodeBadParam)
}

func TestParseLsTree(t *testing.T) {
	out := "100644 blob aaa 12\tb.txt\x00040000 tree bbb -\ta\x00120000 blob ccc 4\tlink\x00160000 commit ddd -\tsub\x00"
	got := parseLsTree(out)
	want := []struct{ name, typ string }{{"a", "dir"}, {"b.txt", "file"}, {"link", "symlink"}, {"sub", "submodule"}}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i, w := range want {
		if got[i].Name != w.name || got[i].Type != w.typ {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], w)
		}
	}
	if got[1].Size == nil || *got[1].Size != 12 || got[0].Size != nil {
		t.Errorf("sizes = %+v %+v", got[0].Size, got[1].Size)
	}
}
