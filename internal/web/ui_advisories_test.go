package web

import (
	"fmt"
	"net/http"
	"testing"

	"scrutineer/internal/db"
)

func TestUIInventoryAdvisories(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	alpha := seedUIRepo(t, s.DB, "alpha")
	beta := seedUIRepo(t, s.DB, "beta")
	fixed := db.Advisory{RepositoryID: alpha.ID, UUID: "GHSA-1111-2222-3333", Title: "Overflow", Severity: "high", CVSSScore: 8.1, Packages: "a,b"}
	bypass := db.Advisory{RepositoryID: beta.ID, UUID: "GHSA-4444-5555-6666", Title: "Injection", Severity: "critical", CVSSScore: 9.8}
	plain := db.Advisory{RepositoryID: beta.ID, UUID: "GHSA-7777-8888-9999", Title: "Leak", Severity: "low", CVSSScore: 2}
	for _, a := range []*db.Advisory{&fixed, &bypass, &plain} {
		if err := s.DB.Create(a).Error; err != nil {
			t.Fatal(err)
		}
	}
	s.DB.Create(&db.AdvisoryAudit{RepositoryID: alpha.ID, AdvisoryUUID: fixed.UUID, Status: advisoryAuditFixed})
	s.DB.Create(&db.AdvisoryAudit{RepositoryID: beta.ID, AdvisoryUUID: bypass.UUID, Status: "bypass"})

	type advList struct {
		uiList[map[string]any]
		Severities []string `json:"severities"`
	}
	list := decodeUIJSON[advList](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/advisories", nil)), http.StatusOK)
	if list.Total != 3 || list.Items[0]["id"] != float64(bypass.ID) {
		t.Fatalf("default (cvss desc) = %+v", list)
	}
	if len(list.Severities) != 3 {
		t.Errorf("severities = %v", list.Severities)
	}
	byID := map[float64]map[string]any{}
	for _, it := range list.Items {
		byID[it["id"].(float64)] = it
	}
	if f := byID[float64(fixed.ID)]; f["audit_status"] != advisoryAuditFixed ||
		f["certificate_url"] != fmt.Sprintf("/advisories/%d/certificate.json", fixed.ID) {
		t.Errorf("fixed row = %v", f)
	}
	if b := byID[float64(bypass.ID)]; b["audit_status"] != "bypass" || b["certificate_url"] != "" {
		t.Errorf("bypass row = %v", b)
	}
	if p := byID[float64(plain.ID)]; p["audit_status"] != "" {
		t.Errorf("never-audited row = %v", p)
	}
	if ref, _ := byID[float64(fixed.ID)]["repository"].(map[string]any); ref["name"] != "alpha" {
		t.Errorf("repository ref = %v", ref)
	}

	repo := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", fmt.Sprintf("/api/v1/ui/advisories?repository_id=%d&sort=title", beta.ID), nil)))
	if repo.Total != 2 || repo.Items[0]["title"] != "Injection" {
		t.Errorf("repository_id+title = %+v", repo)
	}
	sev := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/advisories?severity=low", nil)))
	if sev.Total != 1 || sev.Items[0]["title"] != "Leak" {
		t.Errorf("severity=low = %+v", sev)
	}
	byRepo := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/advisories?sort=repository.desc", nil)))
	if ref, _ := byRepo.Items[0]["repository"].(map[string]any); ref["name"] != "beta" {
		t.Errorf("sort=repository.desc first = %v", byRepo.Items[0])
	}
	q := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/advisories?q=4444", nil)))
	if q.Total != 1 {
		t.Errorf("q by uuid = %+v", q)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/advisories?repository_id=abc", nil)), http.StatusBadRequest, uiCodeBadParam)
}
