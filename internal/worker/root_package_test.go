package worker

import (
	"testing"

	"scrutineer/internal/db"
)

func TestSubprojectsRootComposerPackage(t *testing.T) {
	report := `{"subprojects":[
		{"path":".","name":"neos/neos-ui","kind":"composer-package","description":"PHP backend with Classes and Configuration at the root."},
		{"path":"packages/utils-redux","name":"@neos-project/utils-redux","kind":"npm-package"}
	]}`
	if problems := ValidateReportSchema(loadBundledSchema(t, "../../skills/subprojects/schema.json"), report); problems != "" {
		t.Fatal(problems)
	}
	repo, gdb := runSkillWithReport(t, "subprojects", report)
	var projects []db.Subproject
	if err := gdb.Where("repository_id = ?", repo.ID).Order("path").Find(&projects).Error; err != nil {
		t.Fatal(err)
	}
	if len(projects) != 2 || projects[0].Path != "." || projects[0].Kind != "composer-package" || projects[0].ScanSubPath() != "" {
		t.Fatalf("root package not preserved: %+v", projects)
	}
	if projects[1].ScanSubPath() != "packages/utils-redux" {
		t.Fatalf("workspace scope changed: %+v", projects[1])
	}
}
