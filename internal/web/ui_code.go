package web

import (
	"context"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/git-pkgs/clone"

	"scrutineer/internal/db"
)

// Code browser JSON (02 #54 blob, #55 tree). Blobs and trees at a full
// commit SHA never change, so they are served immutable-cached with an
// ETag of "<commit>:<path>"; abbreviated SHAs (which a later fetch could
// re-resolve) and every error state are no-store.

const (
	fullSHA1Len   = 40
	fullSHA256Len = 64
	immutableFor  = "private, max-age=31536000, immutable"
	treeMaxDepth  = 2
	// treeMaxEntries caps one directory listing so a pathological tree
	// cannot produce an unbounded response.
	treeMaxEntries = 5000
)

// uiBlobView is BlobView. size_bytes precedes content so a streaming client
// can choose worker-side highlighting before the body arrives.
type uiBlobView struct {
	Repo           uiRepoRef `json:"repo"`
	Commit         string    `json:"commit"`
	Path           string    `json:"path"`
	Language       string    `json:"language"`
	SizeBytes      int       `json:"size_bytes"`
	Truncated      bool      `json:"truncated"`
	Highlight      [2]int    `json:"highlight"`
	ForgeURL       string    `json:"forge_url"`
	ForgeCommitURL string    `json:"forge_commit_url"`
	Local          bool      `json:"local"`
	Missing        bool      `json:"missing,omitempty"`
	Error          string    `json:"error,omitempty"`
	Unsupported    bool      `json:"unsupported,omitempty"`
	Content        string    `json:"content"`
}

type uiRepoRef struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

// isFullSHA reports a full (immutable) commit id.
func isFullSHA(commit string) bool {
	return len(commit) == fullSHA1Len || len(commit) == fullSHA256Len
}

// uiCodeTarget parses {id}, {commit} and {path...}. allowRoot accepts an
// empty path (the tree root).
func (s *Server) uiCodeTarget(w http.ResponseWriter, r *http.Request, allowRoot bool) (db.Repository, string, string, bool) {
	repo, ok := s.uiLoadRepo(w, r)
	if !ok {
		return repo, "", "", false
	}
	commit := r.PathValue(uiKeyCommit)
	if !clone.ValidCommit(commit) {
		uiBadParam(w, "bad commit")
		return repo, "", "", false
	}
	raw := strings.Trim(r.PathValue("path"), "/")
	if raw == "" && allowRoot {
		return repo, commit, "", true
	}
	clean, ok := sanitizeBlobPath(raw)
	if !ok {
		uiBadParam(w, "bad path")
		return repo, "", "", false
	}
	return repo, commit, clean, true
}

// ensureCodeCommit resolves the checkout for repo and makes sure commit is
// present (deepening the shallow cache clone for a remote repo). missing is
// true when there is no checkout at all; err is a git/fetch failure.
func (s *Server) ensureCodeCommit(ctx context.Context, repo db.Repository, commit string) (dir string, local, missing bool, err error) {
	dir, local = s.codeRepoDir(repo)
	if _, statErr := os.Stat(filepath.Join(dir, ".git")); statErr != nil {
		return dir, local, true, nil
	}
	if !local {
		if err := s.Worker.EnsureCommit(ctx, repo.URL, commit); err != nil {
			return dir, local, false, err
		}
	}
	return dir, local, false, nil
}

// setCodeCache applies the immutable-or-no-store rule and answers a matching
// If-None-Match with 304. It returns false when the 304 was written.
func setCodeCache(w http.ResponseWriter, r *http.Request, commit, p string, cacheable bool) bool {
	if !cacheable || !isFullSHA(commit) {
		w.Header().Set(cacheControlHeader, noStore)
		return true
	}
	etag := `"` + commit + ":" + p + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set(cacheControlHeader, immutableFor)
	if inm := r.Header.Get("If-None-Match"); inm != "" && (inm == etag || inm == "*") {
		w.WriteHeader(http.StatusNotModified)
		return false
	}
	return true
}

// ---------------------------------------------------------------- #54 blob

func (s *Server) uiRepoBlob(w http.ResponseWriter, r *http.Request) {
	repo, commit, p, ok := s.uiCodeTarget(w, r, false)
	if !ok {
		return
	}
	view := s.loadBlobView(r.Context(), repo, commit, p)
	view.Highlight = parseHighlight(r.URL.Query().Get("line"))
	if !setCodeCache(w, r, commit, p, !view.Missing && view.Error == "") {
		return
	}
	writeUIJSON(w, http.StatusOK, view)
}

// loadBlobView reads <commit>:<path> the way repoBlob does; the missing,
// error and unsupported states are flags on a 200, as on the HTML page.
func (s *Server) loadBlobView(ctx context.Context, repo db.Repository, commit, p string) uiBlobView {
	view := uiBlobView{
		Repo:           uiRepoRef{ID: repo.ID, Name: repo.Name},
		Commit:         commit,
		Path:           p,
		ForgeURL:       forgeBlobURL(repo.HTMLURL, commit, p, 0),
		ForgeCommitURL: forgeCommitURL(repo.HTMLURL, commit),
	}
	dir, local, missing, err := s.ensureCodeCommit(ctx, repo, commit)
	view.Local = local
	switch {
	case missing:
		view.Missing = true
		return view
	case err != nil:
		view.Error = err.Error()
		return view
	}
	blob, err := gitShowBlob(ctx, dir, commit, p)
	if err != nil {
		view.Error = err.Error()
		return view
	}
	view.SizeBytes = len(blob.Content)
	view.Truncated = blob.Truncated
	view.Language = highlightLang(p, blob.Detection.Format)
	if !renderableBlob(blob.Detection) {
		view.Unsupported = true
		return view
	}
	view.Content = string(blob.Content)
	return view
}

// ---------------------------------------------------------------- #55 tree

// uiTreeEntry is one directory entry; Entries is filled for directories at
// depth=2.
type uiTreeEntry struct {
	Name    string        `json:"name"`
	Type    string        `json:"type"`
	Size    *int64        `json:"size"`
	Entries []uiTreeEntry `json:"entries,omitempty"`
}

func (s *Server) uiRepoTree(w http.ResponseWriter, r *http.Request) {
	repo, commit, p, ok := s.uiCodeTarget(w, r, true)
	if !ok {
		return
	}
	depth := 1
	if v := r.URL.Query().Get("depth"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > treeMaxDepth {
			uiBadParam(w, "depth must be 1 or 2")
			return
		}
		depth = n
	}
	dir, local, missing, err := s.ensureCodeCommit(r.Context(), repo, commit)
	switch {
	case missing:
		w.Header().Set(cacheControlHeader, noStore)
		writeUIJSON(w, http.StatusOK, map[string]any{"path": p, "entries": []uiTreeEntry{}, "missing": true, "local": local})
		return
	case err != nil:
		w.Header().Set(cacheControlHeader, noStore)
		writeUIJSON(w, http.StatusOK, map[string]any{"path": p, "entries": []uiTreeEntry{}, errorKey: err.Error(), "local": local})
		return
	}
	entries, err := listTree(r.Context(), dir, commit, p, depth)
	if err != nil {
		if os.IsNotExist(err) {
			uiNotFound(w, "path")
			return
		}
		w.Header().Set(cacheControlHeader, noStore)
		writeUIJSON(w, http.StatusOK, map[string]any{"path": p, "entries": []uiTreeEntry{}, errorKey: err.Error(), "local": local})
		return
	}
	if !setCodeCache(w, r, commit, p+"/", true) {
		return
	}
	writeUIJSON(w, http.StatusOK, map[string]any{"path": p, "entries": entries, "local": local})
}

// listTree lists the tree at <commit>:<p> with `git ls-tree`, descending one
// more level into directories when depth is 2. A path that is not a
// directory at commit is os.ErrNotExist.
func listTree(ctx context.Context, dir, commit, p string, depth int) ([]uiTreeEntry, error) {
	out, err := clone.Run(ctx, dir, []string{"GIT_TERMINAL_PROMPT=0"}, "ls-tree", "-z", "-l", commit+":"+p)
	if err != nil {
		if strings.Contains(out, "Not a valid object name") || strings.Contains(out, "not a tree object") {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	entries := parseLsTree(out)
	if depth > 1 {
		for i := range entries {
			if entries[i].Type != "dir" {
				continue
			}
			sub, err := listTree(ctx, dir, commit, path.Join(p, entries[i].Name), 1)
			if err != nil {
				return nil, err
			}
			entries[i].Entries = sub
		}
	}
	return entries, nil
}

// parseLsTree parses `git ls-tree -z -l` output: "<mode> <type> <object>
// <size>\t<name>" records separated by NUL. Directories sort first, then by
// name.
func parseLsTree(out string) []uiTreeEntry {
	entries := []uiTreeEntry{}
	for rec := range strings.SplitSeq(out, "\x00") {
		meta, name, ok := strings.Cut(rec, "\t")
		if !ok || name == "" {
			continue
		}
		fields := strings.Fields(meta)
		const lsTreeFields = 4
		if len(fields) < lsTreeFields {
			continue
		}
		e := uiTreeEntry{Name: name}
		switch {
		case fields[0] == "120000":
			e.Type = "symlink"
		case fields[1] == "tree":
			e.Type = "dir"
		case fields[1] == uiKeyCommit:
			e.Type = "submodule"
		default:
			e.Type = "file"
		}
		if n, err := strconv.ParseInt(fields[3], 10, 64); err == nil {
			e.Size = &n
		}
		entries = append(entries, e)
		if len(entries) >= treeMaxEntries {
			break
		}
	}
	slices.SortStableFunc(entries, func(a, b uiTreeEntry) int {
		if (a.Type == "dir") != (b.Type == "dir") {
			if a.Type == "dir" {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	return entries
}
