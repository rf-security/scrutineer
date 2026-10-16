package worker

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/alpha-omega-security/harness"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

type claudeCostReplayRunner struct {
	stream string
	report string
	parser Harness
	after  func()
}

func (claudeCostReplayRunner) Backend() string { return "claude" }

func (claudeCostReplayRunner) SkillDir(root, name string) string {
	return ClaudeHarness{}.SkillDir(root, name)
}

func (r claudeCostReplayRunner) RunSkill(_ context.Context, _ SkillJob, emit func(Event)) (SkillResult, error) {
	parser := r.parser
	if parser == nil {
		parser = ClaudeHarness{}
	}
	parser.ParseStream(strings.NewReader(r.stream), emit)
	if r.after != nil {
		r.after()
	}
	report := r.report
	if report == "" {
		report = `{"tier":"ready","summary":"ok"}`
	}
	return SkillResult{Report: report}, nil
}

func TestQueuedClaudeScanPreservesZeroIncrementalResultCost(t *testing.T) {
	stream := strings.Join([]string{
		`{"type":"system","subtype":"init","session_id":"session-1"}`,
		`{"type":"result","subtype":"success","session_id":"session-1","result":"launched","total_cost_usd":0.04407415,"num_turns":2,"usage":{"input_tokens":18,"output_tokens":297,"cache_read_input_tokens":37822,"cache_creation_input_tokens":6161}}`,
		`{"type":"system","subtype":"init","session_id":"session-1"}`,
		`{"type":"result","subtype":"success","session_id":"session-1","result":"hello","total_cost_usd":0.04407415,"num_turns":1,"usage":{"input_tokens":10,"output_tokens":60,"cache_read_input_tokens":22787,"cache_creation_input_tokens":1452}}`,
	}, "\n")
	w, _, scanID := newQueuedSchemaSkillWorker(t, true, claudeCostReplayRunner{stream: stream})
	if err := w.DB.Model(&db.Scan{}).Where("id = ?", scanID).Update("model", "claude-haiku-4-5").Error; err != nil {
		t.Fatal(err)
	}
	got := runQueuedCostScan(t, w, scanID)
	t.Logf("persisted scan: cost=$%.8f turns=%d input=%d output=%d", got.CostUSD, got.Turns, got.InputTokens, got.OutputTokens)
	if math.Abs(got.CostUSD-0.04407415) > 1e-12 || got.SessionCostUSD != 0.04407415 {
		t.Errorf("saved costs = %.8f / %.8f, want 0.04407415", got.CostUSD, got.SessionCostUSD)
	}
	if got.Turns != 3 || got.InputTokens != 28 || got.OutputTokens != 357 {
		t.Errorf("saved token accounting = %+v", got)
	}
}

func runQueuedCostScan(t *testing.T, w *Worker, scanID uint) db.Scan {
	t.Helper()
	sqlDB, err := w.DB.DB()
	if err != nil {
		t.Fatal(err)
	}
	q, err := queue.New(sqlDB, w.Log, 1, queue.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	w.Register(q)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	done := make(chan struct{})
	go func() {
		q.Start(ctx)
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done })
	if err := q.Enqueue(ctx, JobSkill, scanID, 0); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var got db.Scan
		if err := w.DB.First(&got, scanID).Error; err != nil {
			t.Fatal(err)
		}
		if got.Status == db.ScanDone {
			return got
		}
		if got.Status.Terminal() {
			t.Fatalf("scan failed: status=%s error=%s", got.Status, got.Error)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("scan did not finish: status=%s error=%s", got.Status, got.Error)
		case <-ticker.C:
		}
	}
}

func TestQueuedScanSessionCostAccounting(t *testing.T) {
	tests := []struct {
		name        string
		parent      bool
		sessionID   string
		baseline    float64
		priorCost   float64
		stream      string
		parser      Harness
		wantCost    float64
		wantSession float64
	}{
		{
			name: "retry uses immediate parent total", parent: true, sessionID: "session-1", baseline: 0.0110936,
			stream: `{"type":"system","subtype":"init","session_id":"session-1"}` + "\n" +
				`{"type":"result","total_cost_usd":0.015707,"usage":{"output_tokens":52}}`,
			wantCost: 0.0046134, wantSession: 0.015707,
		},
		{
			name: "paused scan resumes on same row", sessionID: "session-1", baseline: 0.0110936, priorCost: 0.0110936,
			stream: `{"type":"system","subtype":"init","session_id":"session-1"}` + "\n" +
				`{"type":"result","total_cost_usd":0.015707,"usage":{"output_tokens":52}}`,
			wantCost: 0.015707, wantSession: 0.015707,
		},
		{
			name: "failed resume starts fresh session", parent: true, sessionID: "session-1", baseline: 0.0110936,
			stream: `{"type":"system","subtype":"init","session_id":"session-2"}` + "\n" +
				`{"type":"result","total_cost_usd":0.0046134,"usage":{"output_tokens":52}}`,
			wantCost: 0.0046134, wantSession: 0.0046134,
		},
		{
			name: "parent from different session is ignored", parent: true, sessionID: "session-2", baseline: 0.0110936,
			stream: `{"type":"system","subtype":"init","session_id":"session-2"}` + "\n" +
				`{"type":"result","total_cost_usd":0.0046134,"usage":{"output_tokens":52}}`,
			wantCost: 0.0046134, wantSession: 0.0046134,
		},
		{
			name: "legacy parent has no recorded total", parent: true, sessionID: "session-1",
			stream: `{"type":"system","subtype":"init","session_id":"session-1"}` + "\n" +
				`{"type":"result","total_cost_usd":0.015707,"usage":{"output_tokens":52}}`,
			wantCost: 0.015707, wantSession: 0.015707,
		},
		{
			name: "copilot checkpoint is cumulative", parent: true, sessionID: "session-1", baseline: 0.01,
			parser: CopilotHarness{},
			stream: `{"type":"session.usage_checkpoint","data":{"totalNanoAiu":1500000000}}` + "\n" +
				`{"type":"result","sessionId":"session-1","exitCode":0}`,
			wantCost: 0.005, wantSession: 0.015,
		},
		{
			name: "copilot without checkpoint remains per invocation", parent: true, sessionID: "session-1", baseline: 0.01,
			parser: CopilotHarness{},
			stream: `{"type":"assistant.usage","data":{"model":"claude-haiku-4.5","inputTokens":1000,"outputTokens":10}}` + "\n" +
				`{"type":"result","sessionId":"session-1","exitCode":0}`,
			wantCost: 0.00105, wantSession: 0.01,
		},
		{
			name: "token only backend still gets estimate", parser: CodexHarness{},
			stream:   `{"type":"turn.completed","usage":{"input_tokens":1000,"output_tokens":10}}`,
			wantCost: harness.CostFromUsage("claude-haiku-4-5", Usage{InputTokens: 1000, OutputTokens: 10}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, repoID, scanID := newQueuedSchemaSkillWorker(t, true, claudeCostReplayRunner{stream: tc.stream, parser: tc.parser})
			updates := map[string]any{"model": "claude-haiku-4-5", "session_id": tc.sessionID, "cost_usd": tc.priorCost}
			if tc.parent {
				root := db.Scan{RepositoryID: repoID, Kind: JobSkill, Status: db.ScanFailed,
					SessionID: "session-1", SessionCostUSD: tc.baseline / 2}
				if err := w.DB.Create(&root).Error; err != nil {
					t.Fatal(err)
				}
				parent := db.Scan{RepositoryID: repoID, Kind: JobSkill, Status: db.ScanFailed,
					SessionID: "session-1", SessionCostUSD: tc.baseline, CostUSD: 0.1,
					ParentScanID: &root.ID, ResumedFromScanID: &root.ID}
				if err := w.DB.Create(&parent).Error; err != nil {
					t.Fatal(err)
				}
				updates["parent_scan_id"] = parent.ID
				updates["resumed_from_scan_id"] = root.ID
			} else {
				updates["session_cost_usd"] = tc.baseline
			}
			if err := w.DB.Model(&db.Scan{}).Where("id = ?", scanID).Updates(updates).Error; err != nil {
				t.Fatal(err)
			}
			got := runQueuedCostScan(t, w, scanID)
			if math.Abs(got.CostUSD-tc.wantCost) > 1e-12 || math.Abs(got.SessionCostUSD-tc.wantSession) > 1e-12 {
				t.Errorf("saved costs = %.8f / %.8f, want %.8f / %.8f", got.CostUSD, got.SessionCostUSD, tc.wantCost, tc.wantSession)
			}
		})
	}
}

type claudeRepairCostRunner struct{ calls int }

func (claudeRepairCostRunner) SkillDir(root, name string) string {
	return ClaudeHarness{}.SkillDir(root, name)
}

func (r *claudeRepairCostRunner) RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	r.calls++
	stream := `{"type":"system","subtype":"init","session_id":"session-1"}` + "\n"
	report := `{"tier":{"invalid":true}}`
	if r.calls == 1 {
		stream += `{"type":"result","total_cost_usd":0.0110936}`
	} else {
		if sj.ResumeSessionID != "session-1" {
			return SkillResult{}, context.Canceled
		}
		stream += `{"type":"result","total_cost_usd":0.015707}`
		report = `{"tier":"ready","summary":"repaired"}`
	}
	return (claudeCostReplayRunner{stream: stream, report: report}).RunSkill(ctx, sj, emit)
}

func TestQueuedClaudeSchemaRepairDoesNotChargeSessionTwice(t *testing.T) {
	runner := &claudeRepairCostRunner{}
	w, _, scanID := newQueuedSchemaSkillWorker(t, true, runner)
	got := runQueuedCostScan(t, w, scanID)
	if runner.calls != 2 || math.Abs(got.CostUSD-0.015707) > 1e-12 {
		t.Fatalf("repair calls=%d saved cost=%.8f", runner.calls, got.CostUSD)
	}
	if !strings.Contains(got.Log, "[result] cost=$0.0046") {
		t.Errorf("repair increment missing from log: %s", got.Log)
	}
}

func TestQueuedScanPersistsCostBeforeRunnerReturns(t *testing.T) {
	stream := `{"type":"system","subtype":"init","session_id":"session-1"}` + "\n" +
		`{"type":"result","total_cost_usd":0.0110936,"num_turns":1,"usage":{"input_tokens":10,"output_tokens":65}}`
	w, _, scanID := newQueuedSchemaSkillWorker(t, true, nil)
	var checkpoint db.Scan
	var readErr error
	w.Runner = claudeCostReplayRunner{stream: stream, after: func() {
		readErr = w.DB.First(&checkpoint, scanID).Error
	}}
	runQueuedCostScan(t, w, scanID)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if checkpoint.Status != db.ScanRunning || checkpoint.CostUSD != 0.0110936 || checkpoint.SessionCostUSD != 0.0110936 ||
		checkpoint.Turns != 1 || checkpoint.InputTokens != 10 || checkpoint.OutputTokens != 65 {
		t.Fatalf("in-flight checkpoint = %+v", checkpoint)
	}
}
