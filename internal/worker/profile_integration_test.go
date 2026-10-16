package worker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIntegration_DetectProjectProfile(t *testing.T) {
	image := os.Getenv("SCRUTINEER_TEST_RUNNER_IMAGE")
	if image == "" {
		t.Skip("set SCRUTINEER_TEST_RUNNER_IMAGE to run profile detection in Docker")
	}
	for _, tt := range []struct {
		name    string
		subPath string
		files   map[string]string
		profile string
	}{
		{"gemspec subproject", "packages/parser", map[string]string{
			"Gemfile":                        "source 'https://rubygems.org'\ngem 'rake'\n",
			"packages/parser/parser.gemspec": "Gem::Specification.new do |spec|\n  spec.name = 'parser'\nend\n",
		}, "ruby"},
		{"gem with secondary Ruby", ".", map[string]string{
			"parser.gemspec": "Gem::Specification.new do |spec|\n  spec.name = 'parser'\nend\n",
			"lib/parser.rb":  "module Parser\nend\n",
			"lib/one.py":     "print('one')\n",
			"lib/two.py":     "print('two')\n",
			"lib/three.py":   "print('three')\n",
		}, "ruby"},
		{"Hoe", ".", map[string]string{
			"Rakefile": "require 'hoe'\nHoe.spec 'parser' do\nend\n",
		}, "ruby"},
		{"alternate Bundler manifest", ".", map[string]string{
			"gems.rb": "source 'https://rubygems.org'\ngem 'rake'\n",
		}, "ruby"},
		{"JavaScript workspace package", "packages/client", map[string]string{
			"composer.json":                `{"name":"example/backend","require":{"php":"*"}}`,
			"package.json":                 `{"private":true,"workspaces":["packages/*"]}`,
			"yarn.lock":                    "# yarn lockfile v1\n",
			"packages/client/package.json": `{"name":"@example/client","private":true}`,
			"packages/client/src/index.ts": "export const client = {};\n",
			"packages/client/src/probe.js": "process.stdout.write('workspace-runtime-ok');\n",
		}, "node"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			work := t.TempDir()
			root := filepath.Join(work, "src")
			for path, content := range tt.files {
				full := filepath.Join(root, path)
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got := DetectProfile(t.Context(), ContainerRuntime{Bin: "docker"}, image, filepath.Join(root, tt.subPath), false)
			if got.Name != tt.profile {
				t.Errorf("DetectProfile = %q, want %s", got.Name, tt.profile)
			}
			if tt.profile == "node" {
				checkWorkspaceNodeRuntime(t, image, work, tt.subPath)
			}
		})
	}
}

func checkWorkspaceNodeRuntime(t *testing.T, image, work, subPath string) {
	t.Helper()
	runner := ContainerRunner{
		Image: image, Runtime: ContainerRuntime{Bin: "docker"}, ProfilesDir: filepath.Join("..", "..", "docker", "profiles"),
		Harness: isolationHarness{stubHarness: stubHarness{guide: "PROFILE.md"}, script: "set -eu; node src/packages/client/src/probe.js > result.txt"},
	}
	result, err := runner.RunSkill(t.Context(), SkillJob{WorkRoot: work, SrcReady: true, SubPath: subPath, Name: "workspace-probe", OutputFile: "result.txt"}, func(e Event) {
		if e.Text != "" {
			t.Log(e.Text)
		}
	})
	if err != nil || result.Profile != "node" {
		t.Fatalf("profile = %q, %v; want node", result.Profile, err)
	}
	if output, err := os.ReadFile(filepath.Join(work, "result.txt")); err != nil || string(output) != "workspace-runtime-ok" {
		t.Fatalf("runtime output = %q, %v", output, err)
	}
}
