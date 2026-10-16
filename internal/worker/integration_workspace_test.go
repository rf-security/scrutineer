package worker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scanWorkspaceMode lets a scan running as a different uid on some runtimes
// write its results into the workspace.
const scanWorkspaceMode = 0o777

// newScanWorkspace returns a workspace for a real-container scan: a temporary
// directory holding an empty src/ that the scan can write probe results into.
func newScanWorkspace(t *testing.T) string {
	t.Helper()
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(work, scanWorkspaceMode); err != nil { //nolint:gosec // test workspace only
		t.Fatal(err)
	}
	return work
}

// readWorkspaceFiles returns the trimmed contents of every regular file at the
// top of a scan workspace, keyed by file name.
func readWorkspaceFiles(dir string) map[string]string {
	files := map[string]string{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil {
			files[e.Name()] = strings.TrimSpace(string(b))
		}
	}
	return files
}
