package worker

import "testing"

func TestPackageManagerModeReports(t *testing.T) {
	triage := loadBundledSchema(t, "../../skills/triage/schema.json")
	audit := loadBundledSchema(t, "../../skills/audit-package-manager/schema.json")
	evidence := `"scope":"Client install command; package metadata is untrusted.","source_sink_inventory":["install.py:12 reads bin names and writes launchers."],"negative_results":[],"unverified_assumptions":[],"design_properties":["install.py:12 writes launchers without executing hooks."]`
	finding := `{"id":"F1","title":"Package bin name escapes install prefix","severity":"High","confidence":"high","cwe":"CWE-22","location":"install.py:12","reachability":"reachable","quality_tier":"high","trace":"The install command joins package-controlled bin names to the prefix before writing.","boundary":"An upstream package author can write outside the selected install prefix.","validation":"Static trace found no containment check between the manifest and file write.","discovered_via":"source","rating":"High because installation can overwrite files belonging to the victim."}`
	for _, tc := range []struct {
		name   string
		schema string
		report string
		valid  bool
	}{
		{"matched", triage, `{"modes":[{"name":"package-manager","evidence":["cmd/install.go: exported install command downloads and installs packages"]}],"triggered":["audit-package-manager","threat-model"]}`, true},
		{"unmatched", triage, `{"modes":[],"gated":["audit-package-manager"]}`, true},
		{"missing evidence", triage, `{"modes":[{"name":"package-manager","evidence":[]}]}`, false},
		{"legacy report", triage, `{"triggered":["threat-model"]}`, true},
		{"not applicable", audit, `{"review_status":"not-applicable","findings":[],"notes":"This application only consumes packages."}`, true},
		{"reviewed", audit, `{"review_status":"reviewed","findings":[],"notes":"Reviewed install paths.",` + evidence + `}`, true},
		{"finding", audit, `{"review_status":"reviewed","findings":[` + finding + `],"notes":"Reviewed install paths.",` + evidence + `}`, true},
		{"finding when not applicable", audit, `{"review_status":"not-applicable","findings":[` + finding + `],"notes":"Consumer only.",` + evidence + `}`, false},
		{"missing audit evidence", audit, `{"review_status":"reviewed","findings":[],"notes":"Reviewed."}`, false},
		{"silent empty report", audit, `{"findings":[]}`, false},
		{"incomplete finding", audit, `{"review_status":"reviewed","findings":[{"title":"Unproven issue"}],"notes":"Reviewed.",` + evidence + `}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateReportSchema(tc.schema, tc.report)
			if (err == "") != tc.valid {
				t.Fatalf("validation = %q, want valid=%v", err, tc.valid)
			}
		})
	}
}
