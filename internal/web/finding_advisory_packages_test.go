package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

func seedAdvisoryPackages(t *testing.T, s *Server, repoID uint, monorepo bool) []db.Package {
	t.Helper()
	other := db.Repository{URL: "https://github.com/other/project"}
	if err := s.DB.Create(&other).Error; err != nil {
		t.Fatal(err)
	}
	foreign := db.Subproject{RepositoryID: other.ID, Path: "cli"}
	if err := s.DB.Create(&foreign).Error; err != nil {
		t.Fatal(err)
	}
	pkgs := []db.Package{
		{RepositoryID: repoID, Name: "unassigned", PURL: "pkg:npm/unassigned@1.0.0"},
		{RepositoryID: other.ID, SubprojectID: &foreign.ID, Name: "foreign", PURL: "pkg:npm/foreign@1.0.0"},
	}
	if monorepo {
		for _, path := range []string{"cli", "web", "empty", "cli/nested"} {
			sub := db.Subproject{RepositoryID: repoID, Path: path}
			if err := s.DB.Create(&sub).Error; err != nil {
				t.Fatal(err)
			}
			if path != "empty" {
				name := strings.ReplaceAll(path, "/", "-")
				pkgs = append(pkgs, db.Package{RepositoryID: repoID, SubprojectID: &sub.ID, Name: name, PURL: "pkg:npm/" + name + "@1.0.0"})
			}
		}
	}
	if err := s.DB.Create(&pkgs).Error; err != nil {
		t.Fatal(err)
	}
	return pkgs
}

func TestFindingAdvisoryPackagesExports(t *testing.T) {
	for _, tt := range []struct {
		name      string
		subPath   string
		location  string
		monorepo  bool
		unlink    bool
		wantNames []string
	}{
		{name: "exact subproject", subPath: "cli", monorepo: true, wantNames: []string{"cli"}},
		{name: "nested subproject", subPath: "cli/nested", monorepo: true, wantNames: []string{"cli-nested"}},
		{name: "no matching packages", subPath: "empty", monorepo: true},
		{name: "missing subproject", subPath: "missing", monorepo: true},
		{name: "root monorepo", monorepo: true},
		{name: "shared code", subPath: "shared", location: "shared/parser.go:10", monorepo: true},
		{name: "location is not attribution", location: "cli/parser.go:10", monorepo: true},
		{name: "foreign links do not enable attribution", subPath: "cli", wantNames: []string{"unassigned"}},
		{name: "legacy root", wantNames: []string{"unassigned"}},
		{name: "unlinked monorepo root", monorepo: true, unlink: true, wantNames: []string{"unassigned", "cli", "web", "cli-nested"}},
		{name: "unlinked monorepo subpath", subPath: "cli", monorepo: true, unlink: true, wantNames: []string{"unassigned", "cli", "web", "cli-nested"}},
		{name: "unlinked monorepo missing path", subPath: "missing", monorepo: true, unlink: true, wantNames: []string{"unassigned", "cli", "web", "cli-nested"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			f := seedCSAFFinding(t, s, func(f *db.Finding) {
				f.SubPath = tt.subPath
				f.Location = tt.location
				f.FixVersion = "1.2.3"
				f.Status = db.FindingFixed
			})
			pkgs := seedAdvisoryPackages(t, s, f.RepositoryID, tt.monorepo)
			if tt.unlink {
				// Attribution disabled: discovery still exists, but packages have no links.
				if err := s.DB.Model(&db.Package{}).Where("repository_id = ?", f.RepositoryID).Update("subproject_id", nil).Error; err != nil {
					t.Fatal(err)
				}
			}
			osv := getOSV(t, s, f.ID)
			csaf := getCSAF(t, s, f.ID)
			bundle := httptest.NewRecorder()
			s.Handler().ServeHTTP(bundle, localReq(http.MethodGet, "/findings/"+strconv.FormatUint(uint64(f.ID), 10)+"/bundle.tar.gz"))
			for _, w := range []*httptest.ResponseRecorder{osv, csaf, bundle} {
				if w.Code != http.StatusOK {
					t.Fatalf("status %d: %s", w.Code, w.Body)
				}
			}
			files := readArchive(t, bundle.Body.Bytes())
			for _, raw := range [][]byte{osv.Body.Bytes(), files["osv.json"]} {
				assertAdvisoryOSVPackages(t, raw, tt.wantNames)
			}
			for _, raw := range [][]byte{csaf.Body.Bytes(), files["csaf.json"]} {
				assertAdvisoryCSAFPackages(t, raw, pkgs, tt.wantNames)
			}
		})
	}
}

func assertAdvisoryOSVPackages(t *testing.T, raw []byte, wantNames []string) {
	t.Helper()
	doc := decodeCSAF(t, raw)
	schema, err := getOSVSchema()
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Fatal(err)
	}
	pkgs, ranges := osvAffectedKinds(t, doc)
	var names []string
	for _, entry := range pkgs {
		pkg := entry["package"].(map[string]any)
		name := pkg["name"].(string)
		names = append(names, name)
		if pkg["purl"] != "pkg:npm/"+name+"@1.0.0" {
			t.Errorf("unexpected package identity: %v", pkg)
		}
		rng := entry["ranges"].([]any)[0].(map[string]any)
		events := rng["events"].([]any)
		if rng["type"] != "SEMVER" || events[1].(map[string]any)["fixed"] != "1.2.3" {
			t.Errorf("unexpected fix range: %v", rng)
		}
	}
	if !slices.Equal(names, wantNames) {
		t.Errorf("OSV package names = %v, want %v", names, wantNames)
	}
	if len(wantNames) == 0 && (len(ranges) != 1 || ranges[0]["ranges"].([]any)[0].(map[string]any)["type"] != "GIT") {
		t.Errorf("expected repository-only GIT fallback, got %v", ranges)
	}
}

func assertAdvisoryCSAFPackages(t *testing.T, raw []byte, pkgs []db.Package, wantNames []string) {
	t.Helper()
	schema, err := getCSAFSchema()
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(decodeCSAF(t, raw)); err != nil {
		t.Fatal(err)
	}
	var doc csafDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	v := doc.Vulnerabilities[0]
	for _, pkg := range pkgs {
		want := slices.Contains(wantNames, pkg.Name)
		id := pkgProductID(pkg)
		if strings.Contains(string(raw), pkg.PURL) != want || strings.Contains(string(raw), `"`+id+`"`) != want {
			t.Errorf("CSAF package %s presence must be %v", pkg.Name, want)
		}
		if slices.Contains(v.ProductStatus.Fixed, id) != want {
			t.Errorf("CSAF fixed products = %v; %s presence must be %v", v.ProductStatus.Fixed, id, want)
		}
		if len(v.Scores) == 0 || slices.Contains(v.Scores[0].Products, id) != want {
			t.Errorf("CSAF scores for %s: %v", id, v.Scores)
		}
		if len(v.Remediations) == 0 || slices.Contains(v.Remediations[0].ProductIDs, id) != want {
			t.Errorf("CSAF remediation for %s: %v", id, v.Remediations)
		}
	}
}

func TestFindingAdvisoryPackagesLookupErrors(t *testing.T) {
	for _, tt := range []struct {
		name    string
		subPath string
		pred    func(*gorm.DB) bool
	}{
		{name: "root link check", pred: tableQuery("packages")},
		{name: "scoped link check", subPath: "cli", pred: tableQuery("packages")},
		{name: "subproject lookup", subPath: "cli", pred: tableQuery("subprojects")},
		{name: "root package rows", pred: advisoryPackageRowsQuery},
		{name: "scoped package rows", subPath: "cli", pred: advisoryPackageRowsQuery},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			f := seedCSAFFinding(t, s, func(f *db.Finding) { f.SubPath = tt.subPath })
			seedAdvisoryPackages(t, s, f.RepositoryID, tt.subPath != "")
			dbErr := errors.New("advisory lookup unavailable")
			failQueries(t, s, tt.pred, dbErr)
			if _, err := findingAdvisoryPackages(s.DB, f, nil); !errors.Is(err, dbErr) {
				t.Fatalf("error = %v, want %v", err, dbErr)
			}
			for _, suffix := range []string{"osv.json", "csaf.json", "bundle.tar.gz"} {
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, localReq(http.MethodGet, "/findings/"+strconv.FormatUint(uint64(f.ID), 10)+"/"+suffix))
				if w.Code != http.StatusInternalServerError {
					t.Errorf("%s status = %d, want 500: %s", suffix, w.Code, w.Body)
				}
			}
		})
	}
}

func advisoryPackageRowsQuery(tx *gorm.DB) bool {
	_, ok := tx.Statement.Dest.(*[]db.Package)
	return ok
}

func TestFindingAdvisoryPackageColumns(t *testing.T) {
	for _, subPath := range []string{"", "cli"} {
		for _, suffix := range []string{"osv.json", "csaf.json", "bundle.tar.gz"} {
			t.Run(subPath+"/"+suffix, func(t *testing.T) {
				s, done := newTestServer(t)
				defer done()
				f := seedCSAFFinding(t, s, func(f *db.Finding) { f.SubPath = subPath })
				seedAdvisoryPackages(t, s, f.RepositoryID, subPath != "")
				var want []string
				if suffix == "osv.json" {
					want = []string{"name", "ecosystem", "p_url"}
				}
				queries := 0
				if err := s.DB.Callback().Query().Before("gorm:query").Register("test:advisory_package_columns", func(tx *gorm.DB) {
					if advisoryPackageRowsQuery(tx) {
						queries++
						if !slices.Equal(tx.Statement.Selects, want) {
							t.Errorf("selected columns = %v, want %v", tx.Statement.Selects, want)
						}
					}
				}); err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, localReq(http.MethodGet, "/findings/"+strconv.FormatUint(uint64(f.ID), 10)+"/"+suffix))
				if w.Code != http.StatusOK || queries == 0 {
					t.Fatalf("status = %d, package queries = %d: %s", w.Code, queries, w.Body)
				}
			})
		}
	}
}
