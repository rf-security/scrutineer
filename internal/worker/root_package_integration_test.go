package worker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
	"scrutineer/internal/queue"
)

func TestIntegration_RootPackageScan(t *testing.T) {
	image := os.Getenv("SCRUTINEER_TEST_RUNNER_IMAGE")
	if image == "" {
		t.Skip("set SCRUTINEER_TEST_RUNNER_IMAGE for container checks")
	}
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/mixed", Name: "mixed"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "root-package-probe", Body: "run the PHP probe", OutputFile: "report.json", OutputKind: "freeform", Version: 1, Active: true, Source: "ui"}
	gdb.Create(&skill)
	project := db.Subproject{RepositoryID: repo.ID, Path: ".", Name: "example/mixed", Kind: "composer-package"}
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, Model: "probe", SkillID: &skill.ID, SubPath: project.ScanSubPath()}
	gdb.Create(&scan)
	runner := ContainerRunner{Image: image, Runtime: ContainerRuntime{Bin: "docker"}, ProfilesDir: filepath.Join("..", "..", "docker", "profiles"),
		Harness: isolationHarness{stubHarness: stubHarness{guide: "PROFILE.md"}, script: "set -eu; test -f src/composer.json; test -f src/Configuration/Policy.yaml; test -f src/packages/client/package.json; php src/Classes/Probe.php > report.json"},
	}
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DataDir: t.TempDir(), Runner: runner, SubprojectScope: "hard",
		PrepareRepoSrc: func(_ context.Context, _, _, work string, _ func(Event)) (string, error) {
			root := filepath.Join(work, "src")
			writeFiles(t, root, map[string]string{
				"composer.json":                `{"name":"example/mixed","autoload":{"psr-4":{"Example\\":"Classes/"}}}`,
				"Classes/Probe.php":            `<?php echo '{"php":"root-runtime-ok"}';`,
				"Configuration/Policy.yaml":    "roles: {}\n",
				"package.json":                 `{"private":true,"workspaces":["packages/*"]}`,
				"packages/client/package.json": `{"name":"@example/client"}`,
			})
			return root, nil
		},
	}
	body, err := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.wrap(w.doSkill)(t.Context(), body); err != nil {
		t.Fatal(err)
	}
	var stored db.Scan
	if err := gdb.First(&stored, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	t.Logf("status=%s profile=%s report=%s", stored.Status, stored.Profile, stored.Report)
	if stored.Status != db.ScanDone || stored.Profile != "php" || stored.Report != `{"php":"root-runtime-ok"}` {
		t.Fatalf("root PHP scan failed: %s\n%s", stored.Error, stored.Log)
	}
}
