package findingnorm

import "testing"

// FindingPath is the single rebase step behind both the novelty check and the
// threat-model control match, so the namespace join and the rejection contract
// are pinned here rather than only through its callers.
func TestFindingPath(t *testing.T) {
	for name, tc := range map[string]struct {
		subPath  string
		location string
		want     string
	}{
		"root-scoped keeps the location's file": {"", "internal/web/server.go:120", "internal/web/server.go"},
		"subpath is prefixed onto the location": {"internal", "web/server.go:120", "internal/web/server.go"},
		"nested subpath joins in order":         {"services/api", "handler.go:8:3", "services/api/handler.go"},
		"line range is stripped":                {"services/api", "handler.go:8-13", "services/api/handler.go"},
		"leading ./ is normalised away":         {"./internal", "./web/server.go", "internal/web/server.go"},

		// A malformed location must produce no match rather than a match
		// against the wrong file, so these yield "" instead of being cleaned.
		"parent escape in location is rejected": {"", "../../etc/passwd:1", ""},
		"parent escape in subpath is rejected":  {"../etc", "passwd", ""},
		"absolute location is rejected":         {"", "/etc/passwd", ""},
		"absolute subpath is rejected":          {"/srv", "server.go", ""},
		"empty location is rejected":            {"internal", "", ""},
		"bare dot is rejected":                  {"", ".", ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := FindingPath(tc.subPath, tc.location); got != tc.want {
				t.Errorf("FindingPath(%q, %q) = %q, want %q", tc.subPath, tc.location, got, tc.want)
			}
		})
	}
}

func TestIsPositionalSuffix(t *testing.T) {
	for input, want := range map[string]bool{
		"42":       true,
		"10-20":    true,
		"":         false,
		"-20":      false,
		"10-":      false,
		"10-20-30": false,
		"line":     false,
		"42:7":     false,
	} {
		if got := IsPositionalSuffix(input); got != want {
			t.Errorf("IsPositionalSuffix(%q) = %t, want %t", input, got, want)
		}
	}
}
