package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundledBuildToolingAuditMetadata(t *testing.T) {
	dir := filepath.Join("..", "..", "skills", "audit-build-tooling")
	skill, err := ParseFile(filepath.Join(dir, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if skill.Name != "audit-build-tooling" || skill.OutputKind != "findings" || skill.Model != "high" || skill.MaxTurns != 48 || skill.MinConfidence != "high" || skill.SchemaJSON == "" {
		t.Fatalf("invalid audit metadata: %+v", skill)
	}
	// Build tools keep real source under directories named build, out, dist or
	// target, such as Bazel's com/google/devtools/build, Go's src/cmd/dist and
	// Buck2's src/target, so only root-level dist and target output is excluded.
	for _, path := range []string{"taskrun/plugins.py", "src/cli.go", "package.json", "Makefile", ".github/workflows/ci.yml", "src/main/java/com/google/devtools/build/lib/Runner.java", "internal/build/exec.go", "cmd/out/main.go", "src/cmd/dist/build.go", "app/buck2_core/src/target/label.rs"} {
		if !PathIncluded(path, skill.Paths, skill.IgnorePaths) {
			t.Errorf("excluded %s", path)
		}
	}
	for _, path := range []string{"node_modules/lib/index.js", "vendor/dep/dep.go", "third_party/lib/a.c", "dist/cli.js", "target/debug/tool", ".cache/entry", "generated/api.go", "cli.min.js"} {
		if PathIncluded(path, skill.Paths, skill.IgnorePaths) {
			t.Errorf("included %s", path)
		}
	}
	ref, err := os.ReadFile(filepath.Join(dir, "references", "threat-model.md"))
	if err != nil {
		t.Fatal(err)
	}
	// Findings persist these links as references, so they must name the
	// immutable v1.0 specification. Draft and latest links keep moving.
	for _, moving := range []string{"/spec/draft/", "/spec/latest/", "/spec/v1.1/", "/main/", "/master/"} {
		if strings.Contains(string(ref), moving) {
			t.Errorf("SLSA links must be pinned to v1.0, found %q", moving)
		}
	}
	if !strings.Contains(string(ref), "https://slsa.dev/spec/v1.0/requirements") || !strings.Contains(string(ref), "https://slsa.dev/spec/v1.0/threats") {
		t.Error("reference must link the versioned SLSA v1.0 requirements and threats")
	}
	for _, section := range []string{"SLSA v1.0", "Workspace trust and auto-execution", "Configuration precedence", "Build cache integrity", "Toolchain and plugin resolution", "Secrets and environment exposure", "Hermeticity and sandboxing claims", "Evidence discipline"} {
		if !strings.Contains(string(ref), section) {
			t.Errorf("reference missing %q", section)
		}
	}
}
