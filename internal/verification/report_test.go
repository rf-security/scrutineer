package verification

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func completeReport() Report {
	criterion := Criterion{Verdict: "pass", Method: "ran PoC", Evidence: "observed", Confidence: "high"}
	root := "AT1"
	return Report{
		Status: "confirmed",
		AttackTree: &AttackTree{
			Goal:    "Trigger the claimed parser panic through the public API",
			RootID:  root,
			Verdict: "reachable",
			Nodes: []AttackTreeNode{
				{ID: root, Kind: "goal", Description: "Trigger parser panic", Status: "satisfied", Evidence: "3/3 attempts panic at parser.go:42"},
				{ID: "AT2", ParentID: &root, Kind: "entry_point", Description: "Supply document to Parse", Status: "satisfied", Evidence: "api.go:18 calls parser"},
				{ID: "AT3", ParentID: ptr("AT2"), Kind: "sink", Description: "Reach parser panic", Status: "satisfied", Evidence: "parser.go:42 panics"},
			},
			Blockers: []string{},
		},
		SeverityPrerequisites: testSeverityPrerequisites("remote_unauthenticated"),
		Attempts: []Attempt{
			{Number: 1, Outcome: "reproduced", Evidence: "boom", FailureClass: "panic", CrashSite: "parser.go:42"},
			{Number: 2, Outcome: "reproduced", Evidence: "boom", FailureClass: "panic", CrashSite: "parser.go:42"},
			{Number: 3, Outcome: "reproduced", Evidence: "boom", FailureClass: "panic", CrashSite: "parser.go:42"},
		},
		Criteria: &Criteria{
			PoCWellFormed:                   criterion,
			ReproducesThreeOfThree:          criterion,
			ClaimedFailureClass:             criterion,
			PublicInterfaceToFirstPartySink: criterion,
			Deterministic:                   criterion,
			ControlBypass:                   &ControlBypass{MatchedControls: []string{}, Assessments: []ControlAssessment{}},
		},
	}
}

func testSeverityPrerequisites(attackerPosition string) *SeverityPrerequisites {
	return &SeverityPrerequisites{
		AttackerPosition:   PrerequisiteValue{Value: attackerPosition, Evidence: "public API accepts remote input"},
		UserInteraction:    PrerequisiteValue{Value: "none", Evidence: "request processing needs no victim action"},
		OutcomeDeterminism: PrerequisiteValue{Value: "deterministic", Evidence: "3/3 attempts reach the same sink"},
		Impact:             PrerequisiteValue{Value: "code_execution_or_equivalent", Evidence: "attempts execute attacker-controlled code"},
		ExistingCapability: PrerequisiteValue{Value: "none", Evidence: "attacker starts without host access"},
	}
}

func TestReportValidateAndScore(t *testing.T) {
	report := completeReport()
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := report.Score(); got != 1 {
		t.Fatalf("score = %v, want 1", got)
	}
	report.Criteria.Deterministic.Verdict = "fail"
	report.Status = "inconclusive"
	if got := report.Score(); got != 0.8 {
		t.Fatalf("score = %v, want 0.8", got)
	}
}

func TestReportValidateRejectsDuplicateAttemptNumbers(t *testing.T) {
	report := completeReport()
	report.Attempts[2].Number = 2
	if err := report.Validate(); err == nil {
		t.Fatal("Validate() accepted duplicate attempt numbers")
	}
}

func TestParseIdentifiesLegacyReport(t *testing.T) {
	_, err := Parse(`{"status":"confirmed","evidence":"boom"}`)
	if !errors.Is(err, ErrMissingRubric) {
		t.Fatalf("Parse() = %v, want ErrMissingRubric", err)
	}
}

func TestParseAcceptsPriorRubricWithoutAttackTree(t *testing.T) {
	report := completeReport()
	report.AttackTree = nil
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.AttackTree != nil {
		t.Fatalf("attack tree = %+v, want nil", parsed.AttackTree)
	}
}

func TestParseAcceptsPriorRubricWithoutControlBypass(t *testing.T) {
	report := completeReport()
	report.Criteria.ControlBypass = nil
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Criteria.ControlBypass != nil {
		t.Fatalf("control bypass = %+v, want nil", parsed.Criteria.ControlBypass)
	}
}

func TestParseAcceptsPriorRubricWithoutSeverityPrerequisites(t *testing.T) {
	report := completeReport()
	report.SeverityPrerequisites = nil
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SeverityPrerequisites != nil {
		t.Fatalf("severity prerequisites = %+v, want nil", parsed.SeverityPrerequisites)
	}
}

func TestReportValidateSeverityPrerequisites(t *testing.T) {
	tests := []struct {
		name   string
		status string
		edit   func(*SeverityPrerequisites)
		want   string
	}{
		{
			name: "invalid value",
			edit: func(p *SeverityPrerequisites) { p.AttackerPosition.Value = "internet" },
			want: `attacker_position.value "internet" is invalid`,
		},
		{
			name: "empty evidence",
			edit: func(p *SeverityPrerequisites) { p.Impact.Evidence = " " },
			want: "impact.evidence is empty",
		},
		{
			name:   "active report cannot skip",
			status: "confirmed",
			edit:   func(p *SeverityPrerequisites) { p.UserInteraction.Value = "not_attempted" },
			want:   "does not permit severity_prerequisites.user_interaction.value not_attempted",
		},
		{
			name:   "not attempted report must skip every row",
			status: "not_attempted",
			want:   "requires severity_prerequisites.attacker_position.value not_attempted",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := completeReport()
			if tc.status != "" {
				report.Status = tc.status
			}
			if tc.edit != nil {
				tc.edit(report.SeverityPrerequisites)
			}
			if err := report.validateSeverityPrerequisites(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateSeverityPrerequisites() = %v, want error containing %q", err, tc.want)
			}
		})
	}

	report := completeReport()
	report.Status = "not_attempted"
	for _, row := range []*PrerequisiteValue{
		&report.SeverityPrerequisites.AttackerPosition,
		&report.SeverityPrerequisites.UserInteraction,
		&report.SeverityPrerequisites.OutcomeDeterminism,
		&report.SeverityPrerequisites.Impact,
		&report.SeverityPrerequisites.ExistingCapability,
	} {
		row.Value = "not_attempted"
		row.Evidence = "setup failed before evaluation"
	}
	if err := report.validateSeverityPrerequisites(); err != nil {
		t.Fatal(err)
	}
}

func TestReportValidateControlBypass(t *testing.T) {
	report := completeReport()
	report.Criteria.ControlBypass = &ControlBypass{
		MatchedControls: []string{"sandbox", "web-authz"},
		Assessments: []ControlAssessment{
			{ControlID: "web-authz", Disposition: "bypassed", Evidence: "attempt reaches handler without authentication"},
			{ControlID: "sandbox", Disposition: "not_applicable", Evidence: "the exercised server path does not enter the sandbox"},
		},
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := report.ValidateControlContext([]string{"web-authz", "sandbox"}, ""); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		edit func(*Report)
		want string
	}{
		{
			name: "missing assessment",
			edit: func(r *Report) { r.Criteria.ControlBypass.Assessments = r.Criteria.ControlBypass.Assessments[:1] },
			want: `no assessment for matched control "sandbox"`,
		},
		{
			name: "duplicate assessment",
			edit: func(r *Report) { r.Criteria.ControlBypass.Assessments[1].ControlID = "web-authz" },
			want: `repeats control "web-authz"`,
		},
		{
			name: "unmatched assessment",
			edit: func(r *Report) { r.Criteria.ControlBypass.Assessments[1].ControlID = "unknown" },
			want: `names unmatched control "unknown"`,
		},
		{
			name: "confirmed unresolved",
			edit: func(r *Report) { r.Criteria.ControlBypass.Assessments[0].Disposition = "unresolved" },
			want: `requires control "web-authz" to be bypassed or not_applicable`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := report
			gate := *report.Criteria.ControlBypass
			gate.MatchedControls = slices.Clone(gate.MatchedControls)
			gate.Assessments = slices.Clone(gate.Assessments)
			criteria := *report.Criteria
			criteria.ControlBypass = &gate
			candidate.Criteria = &criteria
			tc.edit(&candidate)
			if err := candidate.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestReportValidateControlContextRejectsMismatch(t *testing.T) {
	report := completeReport()
	report.Criteria.ControlBypass = &ControlBypass{
		MatchedControls: []string{"model-only"},
		Assessments:     []ControlAssessment{{ControlID: "model-only", Disposition: "bypassed", Evidence: "claimed"}},
	}
	err := report.ValidateControlContext([]string{"host-control"}, "")
	if err == nil || !strings.Contains(err.Error(), "do not match host-resolved controls") {
		t.Fatalf("ValidateControlContext() = %v, want ID mismatch", err)
	}
	report.Criteria.ControlBypass = &ControlBypass{MatchedControls: []string{}, Assessments: []ControlAssessment{}}
	err = report.ValidateControlContext(nil, "the repository threat model could not be read")
	if err == nil || !strings.Contains(err.Error(), "does not match host-resolved reason") {
		t.Fatalf("ValidateControlContext() = %v, want unavailable-reason mismatch", err)
	}
}

func TestReportValidateUnavailableControlContext(t *testing.T) {
	report := completeReport()
	report.Criteria.ControlBypass = &ControlBypass{
		MatchedControls:   []string{},
		Assessments:       []ControlAssessment{},
		UnavailableReason: "the repository threat model could not be read",
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := report.ValidateControlContext(nil, report.Criteria.ControlBypass.UnavailableReason); err != nil {
		t.Fatal(err)
	}
	report.Criteria.ControlBypass.MatchedControls = []string{"invented"}
	if err := report.Validate(); err == nil || !strings.Contains(err.Error(), "requires empty matched_controls") {
		t.Fatalf("Validate() = %v, want unavailable context shape error", err)
	}
}

func TestReportValidateRejectsInvalidAttackTrees(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Report)
		want string
	}{
		{
			name: "duplicate node",
			edit: func(r *Report) { r.AttackTree.Nodes[1].ID = r.AttackTree.Nodes[0].ID },
			want: "is not unique",
		},
		{
			name: "missing parent",
			edit: func(r *Report) {
				missing := "AT99"
				r.AttackTree.Nodes[1].ParentID = &missing
			},
			want: "names missing parent",
		},
		{
			name: "cycle",
			edit: func(r *Report) {
				r.AttackTree.Nodes[1].ParentID = ptr("AT3")
			},
			want: "parent cycle",
		},
		{
			name: "second goal",
			edit: func(r *Report) { r.AttackTree.Nodes[1].Kind = "goal" },
			want: "has kind goal but is not the root",
		},
		{
			name: "status mismatch",
			edit: func(r *Report) { r.AttackTree.Verdict = "blocked" },
			want: `status "confirmed" requires attack_tree.verdict "reachable"`,
		},
		{
			name: "root status mismatch",
			edit: func(r *Report) { r.AttackTree.Nodes[0].Status = "unproven" },
			want: `root status "unproven" does not match verdict "reachable"`,
		},
		{
			name: "reachable without entry point",
			edit: func(r *Report) { r.AttackTree.Nodes[1].Kind = "transition" },
			want: "requires an entry_point node",
		},
		{
			name: "reachable without sink",
			edit: func(r *Report) { r.AttackTree.Nodes[2].Kind = "effect" },
			want: "requires a sink node",
		},
		{
			name: "inconclusive reachable tree",
			edit: func(r *Report) {
				r.Status = "inconclusive"
			},
			want: `status "inconclusive" requires attack_tree.verdict "blocked" or "unproven"`,
		},
		{
			name: "too many nodes",
			edit: func(r *Report) {
				for i := len(r.AttackTree.Nodes); i <= attackTreeMaxNodes; i++ {
					id := fmt.Sprintf("AT%d", i+1)
					r.AttackTree.Nodes = append(r.AttackTree.Nodes, AttackTreeNode{
						ID: id, ParentID: ptr("AT1"), Kind: "transition", Description: "step", Status: "satisfied", Evidence: "observed",
					})
				}
			},
			want: "maximum is 64",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := completeReport()
			tc.edit(&report)
			if err := report.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func ptr(value string) *string {
	return &value
}
