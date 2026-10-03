package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundledWebAuditMetadata(t *testing.T) {
	dir := filepath.Join("..", "..", "skills", "audit-web")
	skill, err := ParseFile(filepath.Join(dir, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if skill.OutputKind != "findings" || skill.Model != "high" || skill.MaxTurns != 48 || skill.MinConfidence != "high" || skill.SchemaJSON == "" {
		t.Fatalf("invalid audit metadata: %+v", skill)
	}
	for _, path := range []string{"app/routes.py", "package-lock.json", "go.sum", "Gemfile.lock"} {
		if !PathIncluded(path, skill.Paths, skill.IgnorePaths) {
			t.Errorf("excluded %s", path)
		}
	}
	for _, path := range []string{"node_modules/lib/index.js", "dist/app.js", "generated/routes.go", "app.min.js"} {
		if PathIncluded(path, skill.Paths, skill.IgnorePaths) {
			t.Errorf("included %s", path)
		}
	}
	ref, err := os.ReadFile(filepath.Join(dir, "references", "threat-model.md"))
	if err != nil {
		t.Fatal(err)
	}
	// Findings persist these links as references, so they must name the
	// immutable release tag. The v5.0.0 branch keeps moving after release.
	if strings.Contains(string(ref), "/v5.0.0/") || !strings.Contains(string(ref), "/v5.0.0_release/") {
		t.Error("ASVS links must be pinned to the v5.0.0_release tag, not the v5.0.0 branch")
	}
	for _, section := range []string{"v5.0.0", "Authentication and sessions", "Tenant and authorization", "Browser origins", "Uploads", "Business workflows", "Evidence discipline"} {
		if !strings.Contains(string(ref), section) {
			t.Errorf("reference missing %q", section)
		}
	}
}
