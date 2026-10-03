package worker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

func newBackendCache(t *testing.T) *BackendPreflightCache {
	t.Helper()
	c, err := NewBackendPreflightCache(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBackendCacheTTLAndConfiguration(t *testing.T) {
	c := newBackendCache(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	calls := 0
	run := func(context.Context) coverage.BackendProbe {
		calls++
		return coverage.BackendProbe{Status: coverage.PreflightReady}
	}
	first, err := c.check(t.Context(), []byte("secret-config"), run)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.check(t.Context(), []byte("secret-config"), run)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !second.Reused || first.Reused || first.ProbeID != second.ProbeID || first.ConfigHash == "secret-config" {
		t.Fatalf("first=%+v second=%+v calls=%d", first, second, calls)
	}
	now = now.Add(time.Hour)
	third, err := c.check(t.Context(), []byte("secret-config"), run)
	if err != nil {
		t.Fatal(err)
	}
	if third.Reused || third.ProbeID == first.ProbeID || calls != 2 {
		t.Fatalf("expired=%+v calls=%d", third, calls)
	}
	if _, err := c.check(t.Context(), []byte("changed-model-tools-or-credentials"), run); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatal("changed config reused cache")
	}
	if newBackendCache(t).key([]byte("secret-config")) == c.key([]byte("secret-config")) {
		t.Fatal("digest is reusable across processes")
	}
}

func TestBackendCacheConcurrentAndCanceledWaiter(t *testing.T) {
	c := newBackendCache(t)
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	run := func(context.Context) coverage.BackendProbe {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return coverage.BackendProbe{Status: coverage.PreflightReady}
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			if _, err := c.check(t.Context(), []byte("same"), run); err != nil {
				t.Error(err)
			}
		})
	}
	<-started
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.check(ctx, []byte("same"), run); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestBackendCacheFailuresAndLeaderCancellation(t *testing.T) {
	c := newBackendCache(t)
	run := func(context.Context) coverage.BackendProbe { return blockedBackendProbe("backend rejected request") }
	first, err := c.check(t.Context(), []byte("bad"), run)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.check(t.Context(), []byte("bad"), run)
	if err != nil || second.Reused || first.ProbeID == second.ProbeID {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	_, err = c.check(ctx, []byte("canceled"), func(context.Context) coverage.BackendProbe {
		cancel()
		return coverage.BackendProbe{Status: coverage.PreflightReady}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	result, err := c.check(t.Context(), []byte("canceled"), run)
	if err != nil || result.Reused {
		t.Fatalf("cancellation cached: %+v %v", result, err)
	}
	for _, ttl := range []time.Duration{0, -time.Second} {
		if _, err := NewBackendPreflightCache(ttl); err == nil {
			t.Fatal("invalid TTL accepted")
		}
	}
}

func TestBackendCacheSharesFailureOnlyWithExistingWaiters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newBackendCache(t)
		release := make(chan struct{})
		results := make(chan coverage.BackendProbe, 4)
		calls := 0
		run := func(context.Context) coverage.BackendProbe {
			calls++
			<-release
			return blockedBackendProbe("temporary failure")
		}
		check := func() {
			result, err := c.check(t.Context(), []byte("same"), run)
			if err != nil {
				t.Error(err)
			}
			results <- result
		}
		go check()
		synctest.Wait()
		for range 3 {
			go check()
		}
		synctest.Wait()
		close(release)
		synctest.Wait()
		var id string
		owners := 0
		for range 4 {
			result := <-results
			if id == "" {
				id = result.ProbeID
			}
			if result.ProbeID != id || result.Status != coverage.PreflightBlocked {
				t.Fatalf("result=%+v", result)
			}
			if !result.Reused {
				owners++
			}
		}
		if calls != 1 || owners != 1 {
			t.Fatalf("calls=%d owners=%d", calls, owners)
		}
		check()
		result := <-results
		if calls != 2 || result.Reused || result.ProbeID == id {
			t.Fatalf("next scan did not re-probe: %+v calls=%d", result, calls)
		}
	})
}

func TestBackendCacheTimeoutReprobes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newBackendCache(t)
		calls := 0
		run := func(ctx context.Context) coverage.BackendProbe {
			calls++
			<-ctx.Done()
			return coverage.BackendProbe{Status: coverage.PreflightReady}
		}
		for range 2 {
			result, err := c.check(t.Context(), []byte("timeout"), run)
			if err != nil || result.Reused || result.Status != coverage.PreflightBlocked || !result.ExpiresAt.Equal(result.CheckedAt) {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		}
		if calls != 2 {
			t.Fatalf("calls=%d", calls)
		}
	})
}

func TestBackendPreflightPersistence(t *testing.T) {
	w, repo := newStreamWorker(t)
	w.BackendPreflight = newBackendCache(t)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanRunning, Kind: JobSkill, Recipe: `{"version":1}`}
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	sj := SkillJob{WorkRoot: t.TempDir()}
	doc := skillContext{Repository: skillContextRepo{Name: "keep"}}
	w.configureCapabilityPreflight(t.Context(), &scan, &db.Skill{}, &sj, doc)
	w.configureBackendPreflight(t.Context(), &scan, &sj, doc)
	if err := sj.RecordPreflight(coverage.Preflight{Status: coverage.PreflightDegraded, Missing: []string{"command:cargo"}, Degraded: true}); err != nil {
		t.Fatal(err)
	}
	run := func(context.Context) coverage.BackendProbe {
		return coverage.BackendProbe{Status: coverage.PreflightReady}
	}
	for range 2 {
		if err := sj.checkBackend(t.Context(), []byte("credential-secret"), run); err != nil {
			t.Fatal(err)
		}
	}
	var receipts []db.ScanPreflightReceipt
	if err := w.DB.Find(&receipts).Error; err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 || receipts[0].RecipeSHA256 != textDigest(scan.Recipe) || strings.Contains(receipts[0].Report, "credential-secret") {
		t.Fatalf("receipts=%+v", receipts)
	}
	if scan.Recipe != `{"version":1}` {
		t.Fatal("claim-time recipe mutated")
	}
	if err := sj.RecordPreflight(coverage.Preflight{Status: coverage.PreflightReady}); err != nil {
		t.Fatal(err)
	}
	rec, ok := coverage.Parse(scan.Coverage)
	if !ok || rec.Preflight.Backend == nil || rec.Preflight.Backend.ReceiptID != receipts[0].ID || rec.Preflight.Status != coverage.PreflightDegraded || scan.Completeness != coverage.CompletenessPartial {
		t.Fatalf("coverage=%s", scan.Coverage)
	}
	contents, err := os.ReadFile(filepath.Join(sj.WorkRoot, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	var staged skillContext
	if err := json.Unmarshal(contents, &staged); err != nil {
		t.Fatal(err)
	}
	if staged.Repository.Name != "keep" || staged.Scrutineer.Preflight.Backend.ProbeID != rec.Preflight.Backend.ProbeID {
		t.Fatalf("context=%s", contents)
	}
	if err := sj.checkBackend(t.Context(), []byte("bad"), func(context.Context) coverage.BackendProbe { return blockedBackendProbe("rejected") }); err == nil {
		t.Fatal("blocked probe allowed scan")
	}
	if err := applySkillCoverageClaim(&scan, coverage.Claim{Receipts: []coverage.Receipt{}}); err != nil {
		t.Fatal(err)
	}
	if scan.Completeness != coverage.CompletenessPartial {
		t.Fatal("claim erased backend failure")
	}
}

func TestBackendPreflightPersistenceFailure(t *testing.T) {
	w, repo := newStreamWorker(t)
	w.BackendPreflight = newBackendCache(t)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanRunning}
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	sj := SkillJob{WorkRoot: t.TempDir()}
	w.configureBackendPreflight(t.Context(), &scan, &sj, skillContext{})
	if err := w.DB.Callback().Update().Before("gorm:update").Register("test:reject_preflight", func(tx *gorm.DB) { _ = tx.AddError(errors.New("forced failure")) }); err != nil {
		t.Fatal(err)
	}
	run := func(context.Context) coverage.BackendProbe {
		return coverage.BackendProbe{Status: coverage.PreflightReady, CostUSD: 1, InputTokens: 10, OutputTokens: 5}
	}
	if err := sj.checkBackend(t.Context(), []byte("key"), run); err == nil {
		t.Fatal("ignored DB failure")
	}
	var count int64
	if err := w.DB.Model(&db.ScanPreflightReceipt{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 || scan.Coverage != "" {
		t.Fatal("partial persistence on rollback")
	}
	if scan.CostUSD != 0 || scan.InputTokens != 0 || scan.OutputTokens != 0 {
		t.Fatal("usage changed despite rollback")
	}
	var stored db.Scan
	if err := w.DB.First(&stored, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.CostUSD != 0 || stored.InputTokens != 0 || stored.OutputTokens != 0 {
		t.Fatal("usage partially committed")
	}
	if _, err := os.Stat(filepath.Join(sj.WorkRoot, "context.json")); !os.IsNotExist(err) {
		t.Fatal("staged uncommitted evidence")
	}
}

func TestBackendPreflightUsageChargedOnce(t *testing.T) {
	w, repo := newStreamWorker(t)
	w.BackendPreflight = newBackendCache(t)
	calls := 0
	run := func(context.Context) coverage.BackendProbe {
		calls++
		return coverage.BackendProbe{Status: coverage.PreflightReady, CostUSD: 0.25, InputTokens: 12, OutputTokens: 4, CacheReadTokens: 2, CacheWriteTokens: 1}
	}
	for i := 0; i < 2; i++ {
		scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanRunning, CostUSD: 1, InputTokens: 10, OutputTokens: 3, CacheReadTokens: 1, CacheWriteTokens: 1}
		if err := w.DB.Create(&scan).Error; err != nil {
			t.Fatal(err)
		}
		sj := SkillJob{WorkRoot: t.TempDir()}
		w.configureBackendPreflight(t.Context(), &scan, &sj, skillContext{})
		if err := sj.checkBackend(t.Context(), []byte("shared"), run); err != nil {
			t.Fatal(err)
		}
		rec, _ := coverage.Parse(scan.Coverage)
		if rec.Preflight.Backend.Reused != (i == 1) {
			t.Fatalf("reused=%v", rec.Preflight.Backend.Reused)
		}
		// Re-recording the originating receipt must not charge it twice.
		if _, err := w.recordBackendPreflight(t.Context(), &scan, *rec.Preflight.Backend); err != nil {
			t.Fatal(err)
		}
		var stored db.Scan
		if err := w.DB.First(&stored, scan.ID).Error; err != nil {
			t.Fatal(err)
		}
		wantCost, wantIn, wantOut, wantRead, wantWrite := 1.0, 10, 3, 1, 1
		if i == 0 {
			wantCost, wantIn, wantOut, wantRead, wantWrite = 1.25, 22, 7, 3, 2
		}
		for _, got := range []db.Scan{scan, stored} {
			if got.CostUSD != wantCost || got.InputTokens != wantIn || got.OutputTokens != wantOut || got.CacheReadTokens != wantRead || got.CacheWriteTokens != wantWrite {
				t.Fatalf("scan %d usage cost=%v input=%d output=%d cache=%d/%d", i, got.CostUSD, got.InputTokens, got.OutputTokens, got.CacheReadTokens, got.CacheWriteTokens)
			}
		}
	}
	if calls != 1 {
		t.Fatalf("probes=%d", calls)
	}
}

func TestBackendPreflightFailedProbeUsageAndEstimatedCost(t *testing.T) {
	w, repo := newStreamWorker(t)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanRunning, Model: "gpt-5.4"}
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	result := coverage.BackendProbe{ProbeID: "failed", Status: coverage.PreflightBlocked, InputTokens: 100, OutputTokens: 10}
	if _, err := w.recordBackendPreflight(t.Context(), &scan, result); err != nil {
		t.Fatal(err)
	}
	want := CostFromUsage(scan.Model, Usage{InputTokens: 100, OutputTokens: 10})
	if want <= 0 || scan.CostUSD != want || scan.InputTokens != 100 || scan.OutputTokens != 10 {
		t.Fatalf("cost=%v want=%v input=%d output=%d", scan.CostUSD, want, scan.InputTokens, scan.OutputTokens)
	}
	if scan.Completeness != coverage.CompletenessPartial {
		t.Fatal("failure cap lost")
	}
}

func TestBackendProbeStream(t *testing.T) {
	skipWithoutPOSIXShell(t)
	const success = `{"type":"result","subtype":"success","result":"SCRUTINEER_BACKEND_READY","total_cost_usd":0.02,"usage":{"input_tokens":2,"output_tokens":3}}`
	for _, tc := range []struct {
		name, output string
		ready        bool
	}{
		{"success", success, true},
		{"empty", "", false},
		{"malformed", "not json", false},
		{"wrong-answer", strings.ReplaceAll(success, backendProbeAnswer, "wrong"), false},
		{"error", `{"type":"result","subtype":"error_during_execution","is_error":true,"result":"credential-secret"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := "printf '%s\\n' '" + tc.output + "'"
			ctx, cancel := context.WithTimeout(t.Context(), time.Second*5)
			defer cancel()
			result := runBackendProbe(ctx, ClaudeHarness{}, hostShell, []string{"-c", script}, os.Environ(), t.TempDir())
			if (result.Status == coverage.PreflightReady) != tc.ready || strings.Contains(result.Error, "credential-secret") {
				t.Fatalf("result=%+v", result)
			}
			if tc.ready && (result.InputTokens != 2 || result.OutputTokens != 3 || result.CostUSD != 0.02) {
				t.Fatalf("usage=%+v", result)
			}
		})
	}
}

func TestBackendProbeCancellation(t *testing.T) {
	skipWithoutPOSIXShell(t)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	result := runBackendProbe(ctx, ClaudeHarness{}, hostShell, []string{"-c", "sleep 30"}, os.Environ(), t.TempDir())
	if result.Status != coverage.PreflightBlocked || time.Since(start) > 5*time.Second {
		t.Fatalf("result=%+v elapsed=%s", result, time.Since(start))
	}
}

func TestBackendProbeOtherStreams(t *testing.T) {
	skipWithoutPOSIXShell(t)
	for _, tc := range []struct {
		name   string
		h      Harness
		stream string
	}{
		{"codex", CodexHarness{}, `{"type":"item.completed","item":{"type":"agent_message","text":"SCRUTINEER_BACKEND_READY"}}
{"type":"turn.completed","usage":{"input_tokens":4,"output_tokens":2}}`},
		{"opencode", OpencodeHarness{}, `{"type":"text","part":{"type":"text","text":"SCRUTINEER_BACKEND_READY"}}
{"type":"step_finish","part":{"type":"step-finish","tokens":{"input":4,"output":2}}}`},
		{"copilot", CopilotHarness{}, `{"type":"assistant.message","data":{"content":"SCRUTINEER_BACKEND_READY","turnId":"0","outputTokens":2}}
{"type":"assistant.turn_end","data":{"turnId":"0"}}
{"type":"result","sessionId":"session","exitCode":0}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runBackendProbe(t.Context(), tc.h, hostShell, []string{"-c", "printf '%s\\n' '" + tc.stream + "'"}, os.Environ(), t.TempDir())
			if result.Status != coverage.PreflightReady {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestBackendProbeRejectsTools(t *testing.T) {
	skipWithoutPOSIXShell(t)
	stream := `{"type":"tool","part":{"type":"tool","tool":"bash","state":{"input":{"command":"secret-command"}}}}
{"type":"text","part":{"type":"text","text":"SCRUTINEER_BACKEND_READY"}}
{"type":"step_finish","part":{"type":"step-finish"}}`
	result := runBackendProbe(t.Context(), OpencodeHarness{}, hostShell, []string{"-c", "printf '%s\\n' '" + stream + "'"}, os.Environ(), t.TempDir())
	if result.Status != coverage.PreflightBlocked || strings.Contains(result.Error, "secret") {
		t.Fatalf("result=%+v", result)
	}
}

func TestBackendCacheBounded(t *testing.T) {
	c := newBackendCache(t)
	for i := 0; i < backendPreflightCacheLimit+10; i++ {
		if _, err := c.check(t.Context(), []byte{byte(i / 256), byte(i % 256)}, func(context.Context) coverage.BackendProbe {
			return coverage.BackendProbe{Status: coverage.PreflightReady}
		}); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.entries) != backendPreflightCacheLimit {
		t.Fatalf("entries=%d", len(c.entries))
	}
}
