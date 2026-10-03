package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

const backendSuccessJSON = `{"type":"result","subtype":"success","result":"SCRUTINEER_BACKEND_READY"}`

func TestBackendProbeChild(t *testing.T) {
	address := os.Getenv("PROBE_TEST_CHILD_ADDRESS")
	if address == "" {
		return
	}
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.Copy(io.Discard, conn)
}

func TestBackendLocalCancellationKillsDescendants(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	deadline := time.Now().Add(10 * time.Second)
	if err := listener.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	writeFakeBin(t, bin, "claude", "#!/bin/sh\n\"$PROBE_TEST_BINARY\" -test.run='^TestBackendProbeChild$'\n")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PROBE_TEST_BINARY", self)
	t.Setenv("PROBE_TEST_CHILD_ADDRESS", listener.Addr().String())
	sj := SkillJob{WorkRoot: t.TempDir(), SrcReady: true, checkBackend: func(ctx context.Context, _ []byte, run func(context.Context) coverage.BackendProbe) error {
		result := run(ctx)
		return errors.New(result.Error)
	}}
	if err := os.Mkdir(filepath.Join(sj.WorkRoot, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := (LocalClaude{}).RunSkill(ctx, sj, func(Event) {})
		done <- err
	}()
	conn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatalf("probe descendant did not start: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled probe allowed the skill to run")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("skill did not return after probe cancellation")
	}
	var b [1]byte
	if _, err := conn.Read(b[:]); errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("probe descendant did not close its connection: %v", err)
	}
}

func TestBackendLocalRateLimitReturnsAccountError(t *testing.T) {
	for _, reset := range []int64{0, time.Now().Add(time.Hour).Unix()} {
		t.Run(fmt.Sprint(reset), func(t *testing.T) {
			w, repo := newStreamWorker(t)
			w.BackendPreflight = newBackendCache(t)
			scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanRunning}
			if err := w.DB.Create(&scan).Error; err != nil {
				t.Fatal(err)
			}
			bin := t.TempDir()
			marker := filepath.Join(bin, "main-ran")
			script := fmt.Sprintf(`#!/bin/sh
case "$*" in
 *SCRUTINEER_BACKEND_READY*) printf '%%s\n' '{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":%d}}';;
 *) touch "$PROBE_MAIN_MARKER";;
esac
`, reset)
			writeFakeBin(t, bin, "claude", script)
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("HOME", t.TempDir())
			t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
			t.Setenv("PROBE_MAIN_MARKER", marker)
			sj := SkillJob{WorkRoot: t.TempDir(), SrcReady: true, Model: "test-model"}
			if err := os.Mkdir(filepath.Join(sj.WorkRoot, "src"), 0o755); err != nil {
				t.Fatal(err)
			}
			w.configureBackendPreflight(t.Context(), &scan, &sj, skillContext{})
			_, err := (LocalClaude{}).RunSkill(t.Context(), sj, func(Event) {})
			var accountErr *AccountError
			if !errors.As(err, &accountErr) {
				t.Fatalf("error=%T %v", err, err)
			}
			var gotReset int64
			if accountErr.ResetAt != nil {
				gotReset = accountErr.ResetAt.Unix()
			}
			if gotReset != reset {
				t.Fatalf("reset=%v want=%d", accountErr.ResetAt, reset)
			}
			finishErroredScan(&scan, "", err, func(Event) {})
			if scan.Status != db.ScanPaused {
				t.Fatalf("status=%s", scan.Status)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("main skill ran after rejected rate limit")
			}
			if len(w.BackendPreflight.entries) != 0 {
				t.Fatal("rate limit cached")
			}
		})
	}
}

func probeCacheCallback(t *testing.T, c *BackendPreflightCache) func(context.Context, []byte, func(context.Context) coverage.BackendProbe) error {
	t.Helper()
	return func(ctx context.Context, config []byte, run func(context.Context) coverage.BackendProbe) error {
		result, err := c.check(ctx, config, run)
		if err != nil {
			return err
		}
		if result.Status != coverage.PreflightReady {
			t.Fatalf("probe failed: %+v", result)
		}
		return nil
	}
}

func TestBackendLocalRunnerUsesCacheAndActualArgs(t *testing.T) {
	bin := t.TempDir()
	log := filepath.Join(bin, "invocations")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$PROBE_TEST_LOG\"\nprintf '%s\\n' '" + backendSuccessJSON + "'\n"
	writeFakeBin(t, bin, "claude", script)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PROBE_TEST_LOG", log)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	c := newBackendCache(t)
	sj := SkillJob{WorkRoot: t.TempDir(), SrcReady: true, Model: "model-a", AllowedTools: "Read,Grep", RequiresCommands: []string{"sh"}, checkBackend: probeCacheCallback(t, c)}
	if err := os.Mkdir(filepath.Join(sj.WorkRoot, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := (LocalClaude{}).RunSkill(t.Context(), sj, func(Event) {}); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), backendProbeAnswer) != 1 || strings.Count(string(data), "--model model-a") != 3 || !strings.Contains(string(data), "--max-turns 1") || !strings.Contains(string(data), "Read,Grep,Skill") {
		t.Fatalf("argv=%s", data)
	}
	sj.AllowedTools = "Read"
	if err := (LocalClaude{}).checkBackendPreflight(t.Context(), sj); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANTHROPIC_API_KEY", "rotated")
	if err := (LocalClaude{}).checkBackendPreflight(t.Context(), sj); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), backendProbeAnswer) != 3 {
		t.Fatalf("key failed to change: %s", data)
	}
}

func TestBackendContainerProbeIsolationAndCache(t *testing.T) {
	bin := t.TempDir()
	log := filepath.Join(bin, "invocations")
	script := `#!/bin/sh
case "$1" in
 image) printf '%s\n' 'sha256:fixture'; exit 0;;
 rm) exit 0;;
esac
printf '%s\n' "$*" >> "$PROBE_TEST_LOG"
for arg in "$@"; do
 case "$arg" in
  *:/work) work=${arg%:/work}; [ -z "$(ls -A "$work")" ] || exit 19;;
 esac
done
printf '%s\n' '` + backendSuccessJSON + `'
`
	runtime := writeFakeBin(t, bin, "runtime", script)
	t.Setenv("PROBE_TEST_LOG", log)
	t.Setenv("ANTHROPIC_API_KEY", "first-credential")
	d := ContainerRunner{Runtime: ContainerRuntime{Bin: runtime}, Image: "fixture", Harness: ClaudeHarness{}, ModelBaseURL: "https://provider.invalid"}
	sj := SkillJob{WorkRoot: t.TempDir(), Model: "model", AllowedTools: "Read", OutputFile: "report.json", ResumeSessionID: "scan-session", Prompt: "scan-secret", checkBackend: probeCacheCallback(t, newBackendCache(t))}
	for range 2 {
		if err := d.checkBackendPreflight(t.Context(), sj, "fixture", hardenedNet{}, opencodeProvider{}, ""); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), backendProbeAnswer) != 1 || strings.Contains(string(data), sj.WorkRoot+":/work") || strings.Contains(string(data), "scan-secret") || strings.Contains(string(data), "scan-session") || !strings.Contains(string(data), "--permission-mode acceptEdits") || !strings.Contains(string(data), "--max-turns 1") || !strings.Contains(string(data), "ANTHROPIC_BASE_URL=https://provider.invalid") {
		t.Fatalf("argv=%s", data)
	}
	nameIndex := strings.Index(string(data), "--name scrutineer-backend-probe-")
	imageIndex := strings.Index(string(data), "-- fixture")
	if nameIndex < 0 || nameIndex >= imageIndex {
		t.Fatalf("container name is not before the option delimiter: %s", data)
	}
	t.Setenv("ANTHROPIC_API_KEY", "second-credential")
	if err := d.checkBackendPreflight(t.Context(), sj, "fixture", hardenedNet{}, opencodeProvider{}, ""); err != nil {
		t.Fatal(err)
	}
	d.ModelBaseURL = "https://changed.invalid"
	if err := d.checkBackendPreflight(t.Context(), sj, "fixture", hardenedNet{}, opencodeProvider{}, ""); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), backendProbeAnswer) != 3 {
		t.Fatalf("did not invalidate: %s", data)
	}
}

func TestBackendPreflightDoesNotBypassStaticBlock(t *testing.T) {
	sj := SkillJob{WorkRoot: t.TempDir(), SrcReady: true, RequiresCommands: []string{"scrutineer-definitely-missing"}, checkBackend: func(context.Context, []byte, func(context.Context) coverage.BackendProbe) error {
		t.Fatal("live probe ran despite static block")
		return nil
	}}
	if _, err := (LocalClaude{}).RunSkill(t.Context(), sj, func(Event) {}); err == nil {
		t.Fatal("static block ignored")
	}
}

func TestBackendKeyIncludesToolsWithoutNativeAllowlistFlag(t *testing.T) {
	bin := writeFakeBin(t, t.TempDir(), "runtime", "#!/bin/sh\nprintf '%s\\n' 'sha256:fixture'\n")
	d := ContainerRunner{Runtime: ContainerRuntime{Bin: bin}, Harness: CodexHarness{}}
	var keys []string
	sj := SkillJob{Model: "model", AllowedTools: "Read", checkBackend: func(_ context.Context, key []byte, _ func(context.Context) coverage.BackendProbe) error {
		keys = append(keys, string(key))
		return nil
	}}
	for _, tools := range []string{"Read", "Read,Bash"} {
		sj.AllowedTools = tools
		if err := d.checkBackendPreflight(t.Context(), sj, "fixture", hardenedNet{}, opencodeProvider{}, ""); err != nil {
			t.Fatal(err)
		}
	}
	if len(keys) != 2 || keys[0] == keys[1] {
		t.Fatal("different harness toolsets shared a key")
	}
}
