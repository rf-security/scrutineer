package worker

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type historyCandidateList struct {
	Head               string   `json:"head"`
	CacheReusable      bool     `json:"cache_reusable"`
	CacheInvalidReason string   `json:"cache_invalid_reason"`
	Shallow            bool     `json:"shallow"`
	Ecosystems         []string `json:"ecosystems"`
	TotalMatched       int      `json:"total_matched"`
	PageOffset         int      `json:"page_offset"`
	Truncated          bool     `json:"truncated"`
	NextCursor         string   `json:"next_cursor"`
	Candidates         []struct {
		Commit       string   `json:"commit"`
		Title        string   `json:"title"`
		MatchedTerms []string `json:"matched_terms"`
	} `json:"candidates"`
}

type historyDiffBatch struct {
	Commits []struct {
		Commit        string   `json:"commit"`
		ChangedPaths  []string `json:"changed_paths"`
		Diff          string   `json:"diff"`
		DiffTruncated bool     `json:"diff_truncated"`
	} `json:"commits"`
}

func historyScriptPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs("../../skills/history/scripts/history_candidates.py")
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func historyGit(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func historyIsAncestor(t *testing.T, repo, ancestor, descendant string) bool {
	t.Helper()
	cmd := exec.Command("git", "-C", repo, "merge-base", "--is-ancestor", ancestor, descendant)
	err := cmd.Run()
	if err == nil {
		return true
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		return false
	}
	t.Fatalf("git merge-base --is-ancestor %s %s: %v", ancestor, descendant, err)
	return false
}

func historyCommit(t *testing.T, repo, message, path, content string) string {
	t.Helper()
	full := filepath.Join(repo, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	historyGit(t, repo, "add", path)
	historyGit(t, repo, "-c", "commit.gpgsign=false", "commit", "-m", message)
	return historyGit(t, repo, "rev-parse", "HEAD")
}

func historyTestRepo(t *testing.T) (string, string) {
	t.Helper()
	repo := t.TempDir()
	historyGit(t, repo, "init")
	historyGit(t, repo, "config", "user.name", "History Test")
	historyGit(t, repo, "config", "user.email", "history@example.invalid")
	historyCommit(t, repo, "initial import", "src/parser.c", "int parse(int n) { return n; }\n")
	largeGuard := "int parse(int n) {\n  if (n > 1024) return -1;\n  return n;\n}\n" + strings.Repeat("/* bounded input */\n", 100)
	securityCommit := historyCommit(t, repo, "fix parser bounds check", "src/parser.c", largeGuard)
	historyCommit(t, repo, "update parser documentation", "README.md", "Parser documentation.\n")
	return repo, securityCommit
}

func runHistoryList(t *testing.T, repo string, extra ...string) historyCandidateList {
	t.Helper()
	args := append([]string{historyScriptPath(t), "list", "--repo", repo}, extra...)
	cmd := exec.Command("python3", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("history list: %v\n%s", err, out)
	}
	var got historyCandidateList
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decode history list: %v\n%s", err, out)
	}
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatalf("decode history list shape: %v\n%s", err, out)
	}
	if _, ok := raw["cache_invalid_reason"].(string); !ok {
		t.Fatalf("cache_invalid_reason = %#v, want JSON string", raw["cache_invalid_reason"])
	}
	return got
}

func TestHistoryCandidates_filtersAndChecksCacheAncestry(t *testing.T) {
	repo, securityCommit := historyTestRepo(t)
	got := runHistoryList(t, repo)
	if got.Shallow {
		t.Error("ordinary test repository reported as shallow")
	}
	if len(got.Ecosystems) != 1 || got.Ecosystems[0] != "c-cpp" {
		t.Fatalf("ecosystems = %v, want [c-cpp]", got.Ecosystems)
	}
	if got.TotalMatched != 1 || len(got.Candidates) != 1 {
		t.Fatalf("candidates = %+v, total = %d, want one", got.Candidates, got.TotalMatched)
	}
	if got.Candidates[0].Commit != securityCommit || got.Candidates[0].Title != "fix parser bounds check" {
		t.Errorf("candidate = %+v, want security commit %s", got.Candidates[0], securityCommit)
	}

	incremental := runHistoryList(t, repo, "--base", securityCommit)
	if !incremental.CacheReusable || incremental.CacheInvalidReason != "" {
		t.Fatalf("cache = reusable %v reason %q", incremental.CacheReusable, incremental.CacheInvalidReason)
	}
	if incremental.TotalMatched != 0 || len(incremental.Candidates) != 0 {
		t.Errorf("incremental candidates = %+v, want none after cached fix", incremental.Candidates)
	}

	invalid := runHistoryList(t, repo, "--base", strings.Repeat("0", 40))
	if invalid.CacheReusable || !strings.Contains(invalid.CacheInvalidReason, "unavailable") {
		t.Errorf("invalid cache = reusable %v reason %q", invalid.CacheReusable, invalid.CacheInvalidReason)
	}
	invalidContinuation := exec.Command(
		"python3", historyScriptPath(t), "list", "--repo", repo,
		"--base", strings.Repeat("0", 40), "--after", securityCommit,
	)
	if out, err := invalidContinuation.CombinedOutput(); err == nil {
		t.Fatalf("history list accepted an invalid continuation base:\n%s", out)
	} else if !strings.Contains(string(out), "--after cannot be used with an invalid --base") {
		t.Fatalf("invalid continuation error = %q", out)
	}

	historyGit(t, repo, "switch", "-c", "rewritten", securityCommit+"^")
	historyCommit(t, repo, "rewrite documentation", "README.md", "Rewritten history.\n")
	nonAncestor := runHistoryList(t, repo, "--base", securityCommit)
	if nonAncestor.CacheReusable || !strings.Contains(nonAncestor.CacheInvalidReason, "not an ancestor") {
		t.Errorf("non-ancestor cache = reusable %v reason %q", nonAncestor.CacheReusable, nonAncestor.CacheInvalidReason)
	}
}

func TestHistoryCandidates_capsDiffsAndDetectsShallowClone(t *testing.T) {
	repo, securityCommit := historyTestRepo(t)
	cmd := exec.Command(
		"python3", historyScriptPath(t), "batch", "--repo", repo,
		"--commit", securityCommit, "--max-diff-bytes", "1024",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("history batch: %v\n%s", err, out)
	}
	var batch historyDiffBatch
	if err := json.Unmarshal(out, &batch); err != nil {
		t.Fatalf("decode history batch: %v\n%s", err, out)
	}
	if len(batch.Commits) != 1 || batch.Commits[0].Commit != securityCommit {
		t.Fatalf("batch = %+v", batch.Commits)
	}
	if !batch.Commits[0].DiffTruncated || !strings.Contains(batch.Commits[0].Diff, "diff truncated") {
		t.Errorf("bounded diff was not marked truncated: %+v", batch.Commits[0])
	}
	if len(batch.Commits[0].ChangedPaths) != 1 || batch.Commits[0].ChangedPaths[0] != "src/parser.c" {
		t.Errorf("changed paths = %v", batch.Commits[0].ChangedPaths)
	}

	clone := filepath.Join(t.TempDir(), "shallow")
	cloneCmd := exec.Command("git", "clone", "--depth", "1", "file://"+repo, clone)
	if cloneOut, cloneErr := cloneCmd.CombinedOutput(); cloneErr != nil {
		t.Fatalf("shallow clone: %v\n%s", cloneErr, cloneOut)
	}
	if got := runHistoryList(t, clone); !got.Shallow {
		t.Error("depth-1 clone was not reported as shallow")
	}
}

func TestHistoryCandidates_paginatesPastCandidateLimit(t *testing.T) {
	repo := t.TempDir()
	historyGit(t, repo, "init")
	historyGit(t, repo, "config", "user.name", "History Test")
	historyGit(t, repo, "config", "user.email", "history@example.invalid")
	base := historyCommit(t, repo, "initial import", "src/parser.c", "int parse(int n) { return n; }\n")

	want := make([]string, 0, 7)
	for i := range 7 {
		want = append(want, historyCommit(
			t, repo, "fix security bounds check", "src/parser.c",
			fmt.Sprintf("int parse(int n) { return n < %d ? n : -1; }\n", i+1),
		))
	}

	firstPage := runHistoryList(t, repo, "--base", base, "--max-candidates", "3")
	if !firstPage.Truncated || firstPage.NextCursor != want[2] {
		t.Fatalf("first page = truncated %v cursor %q, want true and %q", firstPage.Truncated, firstPage.NextCursor, want[2])
	}
	resumed := runHistoryList(
		t, repo,
		"--head", firstPage.Head,
		"--base", base,
		"--after", firstPage.NextCursor,
		"--max-candidates", "10",
	)
	if !resumed.CacheReusable || resumed.TotalMatched != len(want) || resumed.PageOffset != 3 || len(resumed.Candidates) != 4 {
		t.Fatalf(
			"resumed page = reusable %v total %d offset %d candidates %d, want true, %d, 3, 4",
			resumed.CacheReusable, resumed.TotalMatched, resumed.PageOffset, len(resumed.Candidates), len(want),
		)
	}
	for i, candidate := range resumed.Candidates {
		if candidate.Commit != want[i+3] {
			t.Fatalf("resumed candidate %d = %s, want %s", i, candidate.Commit, want[i+3])
		}
	}

	var got []string
	cursor := ""
	for pageNumber := 0; ; pageNumber++ {
		extra := []string{"--base", base, "--max-candidates", "3"}
		if cursor != "" {
			extra = append(extra, "--after", cursor)
		}
		page := runHistoryList(t, repo, extra...)
		if page.TotalMatched != len(want) {
			t.Fatalf("page %d total = %d, want %d", pageNumber, page.TotalMatched, len(want))
		}
		if page.PageOffset != len(got) {
			t.Fatalf("page %d offset = %d, want %d", pageNumber, page.PageOffset, len(got))
		}
		for _, candidate := range page.Candidates {
			got = append(got, candidate.Commit)
		}
		if !page.Truncated {
			if page.NextCursor != "" {
				t.Fatalf("final page cursor = %q, want empty", page.NextCursor)
			}
			break
		}
		if page.NextCursor == "" {
			t.Fatalf("page %d is truncated without a continuation cursor", pageNumber)
		}
		cursor = page.NextCursor
	}

	if !slices.Equal(got, want) {
		t.Fatalf("paginated candidates = %v, want %v", got, want)
	}

	newCommit := historyCommit(
		t, repo, "fix security bounds check", "src/parser.c",
		"int parse(int n) { return n < 99 ? n : -1; }\n",
	)
	pinned := runHistoryList(
		t, repo,
		"--head", firstPage.Head,
		"--base", base,
		"--after", firstPage.NextCursor,
		"--max-candidates", "10",
	)
	if len(pinned.Candidates) != 4 || pinned.Candidates[len(pinned.Candidates)-1].Commit != want[len(want)-1] {
		t.Fatalf("pinned continuation included commits outside %s: %+v", firstPage.Head, pinned.Candidates)
	}
	incremental := runHistoryList(t, repo, "--base", firstPage.Head)
	if len(incremental.Candidates) != 1 || incremental.Candidates[0].Commit != newCommit {
		t.Fatalf("incremental candidates = %+v, want only %s", incremental.Candidates, newCommit)
	}
}

func TestHistoryCandidates_mergedHistoryKeepsBaseAndCursorSeparate(t *testing.T) {
	repo := t.TempDir()
	historyGit(t, repo, "init")
	historyGit(t, repo, "config", "user.name", "History Test")
	historyGit(t, repo, "config", "user.email", "history@example.invalid")
	base := historyCommit(t, repo, "initial import", "src/base.c", "int base(void) { return 0; }\n")
	mainBranch := historyGit(t, repo, "branch", "--show-current")

	historyGit(t, repo, "switch", "-c", "left")
	historyCommit(t, repo, "fix security left bounds", "src/left.c", "int left(void) { return 1; }\n")
	historyCommit(t, repo, "fix security left validation", "src/left.c", "int left(void) { return 2; }\n")

	historyGit(t, repo, "switch", "-c", "right", base)
	historyCommit(t, repo, "fix security right bounds", "src/right.c", "int right(void) { return 1; }\n")
	historyCommit(t, repo, "fix security right validation", "src/right.c", "int right(void) { return 2; }\n")

	historyGit(t, repo, "switch", mainBranch)
	historyGit(t, repo, "-c", "commit.gpgsign=false", "merge", "--no-ff", "left", "-m", "merge left")
	historyGit(t, repo, "-c", "commit.gpgsign=false", "merge", "--no-ff", "right", "-m", "merge right")

	full := runHistoryList(t, repo, "--base", base, "--max-candidates", "100")
	if len(full.Candidates) != 4 {
		t.Fatalf("merged history candidates = %+v, want four", full.Candidates)
	}
	want := make([]string, 0, len(full.Candidates))
	for _, candidate := range full.Candidates {
		want = append(want, candidate.Commit)
	}

	split := -1
	reviewedSibling := ""
	for index := 1; index < len(want)-1 && split == -1; index++ {
		for _, prior := range want[:index] {
			if !historyIsAncestor(t, repo, prior, want[index]) {
				split = index
				reviewedSibling = prior
				break
			}
		}
	}
	if split == -1 {
		t.Fatal("test history did not produce a sibling-branch cursor")
	}

	firstPage := runHistoryList(t, repo, "--base", base, "--max-candidates", fmt.Sprint(split+1))
	if !firstPage.Truncated || firstPage.NextCursor != want[split] {
		t.Fatalf("first page = truncated %v cursor %q, want true and %q", firstPage.Truncated, firstPage.NextCursor, want[split])
	}

	wrongBase := runHistoryList(t, repo, "--base", firstPage.NextCursor, "--max-candidates", "100")
	wrongCommits := make([]string, 0, len(wrongBase.Candidates))
	for _, candidate := range wrongBase.Candidates {
		wrongCommits = append(wrongCommits, candidate.Commit)
	}
	if !slices.Contains(wrongCommits, reviewedSibling) {
		t.Fatalf("cursor-as-base did not reproduce reviewed sibling %s: %v", reviewedSibling, wrongCommits)
	}

	resumed := runHistoryList(
		t, repo,
		"--head", firstPage.Head,
		"--base", base,
		"--after", firstPage.NextCursor,
		"--max-candidates", "100",
	)
	got := append([]string(nil), want[:split+1]...)
	for _, candidate := range resumed.Candidates {
		got = append(got, candidate.Commit)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("resumed merged candidates = %v, want %v", got, want)
	}
}

func TestHistoryCandidates_rejectsInvalidScopePaths(t *testing.T) {
	repo, _ := historyTestRepo(t)
	for _, path := range []string{"/absolute", "../outside", "src/../outside", `src\parser.c`} {
		t.Run(path, func(t *testing.T) {
			cmd := exec.Command("python3", historyScriptPath(t), "list", "--repo", repo, "--path", path)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("history list accepted invalid path %q", path)
			}
			if !strings.Contains(string(out), "normalized repository-relative path") {
				t.Fatalf("history list error = %q", out)
			}
		})
	}
}
