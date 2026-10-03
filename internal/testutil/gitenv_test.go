package testutil

import (
	"os/exec"
	"strings"
	"testing"
)

func TestGitEnvDisablesAutomaticMaintenance(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	for _, inherited := range []bool{false, true} {
		name := "no runtime config"
		if inherited {
			name = "preserves runtime config"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("GIT_CONFIG_COUNT", "0")
			if inherited {
				t.Setenv("GIT_CONFIG_COUNT", "3")
				t.Setenv("GIT_CONFIG_KEY_0", "maintenance.auto")
				t.Setenv("GIT_CONFIG_VALUE_0", "true")
				t.Setenv("GIT_CONFIG_KEY_1", "gc.auto")
				t.Setenv("GIT_CONFIG_VALUE_1", "1")
				t.Setenv("GIT_CONFIG_KEY_2", "url.file:///fixture.insteadOf")
				t.Setenv("GIT_CONFIG_VALUE_2", "https://fixture.test/repo")
			}
			want := map[string]string{"maintenance.auto": "false", "gc.auto": "0"}
			if inherited {
				want["url.file:///fixture.insteadOf"] = "https://fixture.test/repo"
			}
			for key, value := range want {
				cmd := exec.Command("git", "config", "--get", key)
				cmd.Dir = t.TempDir()
				cmd.Env = GitEnv()
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("git config --get %s: %v: %s", key, err, out)
				}
				if got := strings.TrimSpace(string(out)); got != value {
					t.Errorf("%s = %q, want %q", key, got, value)
				}
			}
		})
	}
}
