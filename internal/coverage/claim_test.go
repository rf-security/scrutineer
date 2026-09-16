package coverage

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestParseClaimAcceptsSkillOwnedEvidence(t *testing.T) {
	raw := json.RawMessage(`{
		"receipts":[
			{"path":"internal/parser.go","disposition":"reviewed_findings"},
			{"path":"cmd/main.go","disposition":"excluded","reason":"generated wrapper"}
		],
		"surfaces":[{"name":"archive extraction","disposition":"reviewed_clean","evidence_ref":"internal/archive.go:42"}],
		"open_questions":["Is the legacy parser enabled in release builds?"],
		"dropped_findings":[{"path":"internal/log.go","reason":"low confidence","detail":"No attacker-controlled source."}]
	}`)
	claim, err := ParseClaim(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(claim.Receipts) != 2 || claim.Receipts[1].Disposition != DispositionExcluded {
		t.Fatalf("receipts = %+v", claim.Receipts)
	}
	if len(claim.Surfaces) != 1 || len(claim.OpenQuestions) != 1 || len(claim.DroppedFindings) != 1 {
		t.Fatalf("claim evidence lost: %+v", claim)
	}
}

func TestParseClaimRejectsMalformedEvidence(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"missing receipts", `{}`, "receipts is required"},
		{"unknown field", `{"receipts":[],"complete":true}`, "unknown field"},
		{"duplicate path", `{"receipts":[{"path":"a.go","disposition":"reviewed_clean"},{"path":"a.go","disposition":"reviewed_findings"}]}`, "duplicates"},
		{"absolute path", `{"receipts":[{"path":"/etc/passwd","disposition":"reviewed_clean"}]}`, "repository-relative"},
		{"parent path", `{"receipts":[{"path":"src/../secret","disposition":"reviewed_clean"}]}`, "repository-relative"},
		{"backslash path", `{"receipts":[{"path":"src\\parser.go","disposition":"reviewed_clean"}]}`, "repository-relative"},
		{"unknown disposition", `{"receipts":[{"path":"a.go","disposition":"complete"}]}`, "invalid"},
		{"missing gap reason", `{"receipts":[{"path":"a.go","disposition":"failed"}]}`, "reason is required"},
		{"blank surface evidence", `{"receipts":[],"surfaces":[{"name":"parser","disposition":"reviewed_clean","evidence_ref":" "}]}`, "evidence_ref"},
		{"blank question", `{"receipts":[],"open_questions":[" "]}`, "open_questions"},
		{"unidentified drop", `{"receipts":[],"dropped_findings":[{"reason":"duplicate"}]}`, "fingerprint or path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseClaim(json.RawMessage(tt.raw))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestApplyClaimReconcilesWithoutReplacingWorkerFields(t *testing.T) {
	rec := Record{
		RequestedMode:  "diff",
		ActualMode:     "diff",
		FallbackReason: "worker-owned",
		Completeness:   CompletenessPartial,
		Reason:         "not reported yet",
		IncludedPaths:  []string{"a.go", "b.go"},
		ThreatModel:    &ThreatModelState{Update: "updated", Material: true},
	}
	claim := Claim{
		Receipts: []Receipt{
			{Path: "a.go", Disposition: DispositionReviewedClean},
			{Path: "b.go", Disposition: DispositionReviewedFindings},
		},
		OpenQuestions: []string{"Does the fallback parser ship?"},
	}
	if gaps := rec.ApplyClaim(claim, rec.IncludedPaths); gaps != nil {
		t.Fatalf("gaps = %v, want none", gaps)
	}
	if rec.Completeness != CompletenessComplete || rec.Reason != "" {
		t.Fatalf("reconciled state = %q (%q)", rec.Completeness, rec.Reason)
	}
	if rec.RequestedMode != "diff" || rec.ActualMode != "diff" || rec.FallbackReason != "worker-owned" {
		t.Fatalf("worker modes changed: %+v", rec)
	}
	if !reflect.DeepEqual(rec.IncludedPaths, []string{"a.go", "b.go"}) || rec.ThreatModel == nil {
		t.Fatalf("worker scope or threat model changed: %+v", rec)
	}
}

func TestApplyClaimReplacesStagingReasonWithReconciledReason(t *testing.T) {
	rec := Record{
		Completeness:  CompletenessPartial,
		Reason:        "scan has not reported receipts for the staged changed files",
		IncludedPaths: []string{"a.go", "b.go"},
	}
	rec.ApplyClaim(Claim{Receipts: []Receipt{{Path: "a.go", Disposition: DispositionReviewedClean}}}, rec.IncludedPaths)
	if rec.Completeness != CompletenessPartial || rec.Reason != "staged work items have no receipt" {
		t.Fatalf("reconciled state = %q (%q)", rec.Completeness, rec.Reason)
	}
}
