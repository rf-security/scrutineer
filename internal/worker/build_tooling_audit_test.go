package worker

import (
	"testing"

	"scrutineer/internal/db"
)

const buildToolingAuditFinding = `{"id":"F1","title":"Task runner executes workspace plugins without a trust check","severity":"High","confidence":"high","cwe":"CWE-829","location":"taskrun/plugins.py:11","reachability":"reachable","quality_tier":"high","trace":"run_task calls load_plugins, which imports and executes every .taskrun/plugins/*.py file from the checkout through exec_module before the requested task starts.","boundary":"The author of an untrusted checkout runs code as the developer or CI account whenever anyone runs any task in it.","validation":"Static trace finds no trust prompt, opt-in flag or allowlist between the workspace plugin directory and exec_module.","discovered_via":"source","rating":"High: arbitrary code execution on opening an untrusted workspace.","references":[{"url":"https://slsa.dev/spec/v1.0/threats","summary":"SLSA v1.0 threats to the build and dependency stages","tags":"slsa"}]}`

func buildToolingAuditReport(findings string) string {
	return `{"review_status":"reviewed","findings":[` + findings + `],"notes":"Static source review only.","scope":"Task runner.","source_sink_inventory":["taskrun/plugins.py:11 executes workspace plugin modules when a task runs."],"negative_results":["taskrun/cache.py:12 validates the digest and keeps restored paths inside the workspace."],"unverified_assumptions":["CI runner isolation was not available in the checkout."],"design_properties":["taskrun/cli.py:12 runs the argv list of the task the user named."]}`
}

// ingestBuildToolingReport ingests a report through the findings path and
// returns the stored findings with their references.
func ingestBuildToolingReport(t *testing.T, report string) ([]db.Finding, []db.FindingReference) {
	t.Helper()
	repo, gdb := runSkillWithReport(t, "findings", report)
	var findings []db.Finding
	var refs []db.FindingReference
	if err := gdb.Where("repository_id = ?", repo.ID).Find(&findings).Error; err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		var forFinding []db.FindingReference
		if err := gdb.Where("finding_id = ?", f.ID).Find(&forFinding).Error; err != nil {
			t.Fatal(err)
		}
		refs = append(refs, forFinding...)
	}
	return findings, refs
}

func TestBuildToolingAuditSchemaAndIngestion(t *testing.T) {
	report := buildToolingAuditReport(buildToolingAuditFinding)
	if detail := ValidateReportSchema(loadBundledSchema(t, "../../skills/audit-build-tooling/schema.json"), report); detail != "" {
		t.Fatal(detail)
	}
	findings, refs := ingestBuildToolingReport(t, report)
	if len(findings) != 1 || findings[0].CWE != "CWE-829" {
		t.Fatalf("findings=%+v", findings)
	}
	if len(refs) != 1 || refs[0].Summary != "SLSA v1.0 threats to the build and dependency stages" {
		t.Fatalf("references=%+v", refs)
	}
}

func TestBuildToolingAuditSchemaRejectsInvalidReports(t *testing.T) {
	checkModeSchemaRejectsInvalid(t, modeSchemaCase{
		schemaPath: "../../skills/audit-build-tooling/schema.json", report: buildToolingAuditReport, finding: buildToolingAuditFinding,
		reference:    `{"url":"https://slsa.dev/spec/v1.0/threats","summary":"SLSA v1.0 threats to the build and dependency stages","tags":"slsa"}`,
		nonMatchNote: "Makefile and build.sh only build this application.",
	})
}
