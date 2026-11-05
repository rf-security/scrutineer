package web

import (
	"fmt"
	"net/http"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

// Tests for the /api/v1/ui finding status and action endpoints (WP-API-2).
// Every enqueue goes through newTestServer's in-memory queue; nothing reaches
// a model.

func uiActPath(id uint, suffix string) string {
	return fmt.Sprintf("/api/v1/ui/findings/%d/%s", id, suffix)
}

// uiActSeed creates a repository, a deep-dive scan and an enriched finding.
func uiActSeed(t *testing.T, s *Server) db.Finding {
	t.Helper()
	repo := seedUIRepo(t, s.DB, "actions")
	sc := seedUIScan(t, s.DB, repo, db.ScanDone, deepDiveSkillName)
	return seedUIFinding(t, s.DB, sc, "Parser overflow", db.FindingEnriched)
}

func uiActSkill(t *testing.T, s *Server, name string) db.Skill {
	t.Helper()
	sk := db.Skill{Name: name, Active: true, Source: "ui", Body: name, OutputKind: "freeform", OutputFile: "report.json"}
	if err := s.DB.Create(&sk).Error; err != nil {
		t.Fatal(err)
	}
	return sk
}

func uiActQueuedScans(t *testing.T, s *Server, findingID uint, skill string) []db.Scan {
	t.Helper()
	var scans []db.Scan
	if err := s.DB.Where("finding_id = ? AND skill_name = ? AND status = ?", findingID, skill, db.ScanQueued).
		Order("id").Find(&scans).Error; err != nil {
		t.Fatal(err)
	}
	return scans
}

// ---------------------------------------------------------------- status

type uiActStatusResponse struct {
	ID       uint           `json:"id"`
	Status   string         `json:"status"`
	Workflow map[string]any `json:"workflow"`
}

func TestUIFindingActionsStatus(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := uiActSeed(t, s)

	w := serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID, "status"), map[string]any{"status": "triaged", "by": "walter"}))
	got := decodeUIJSON[uiActStatusResponse](t, w, http.StatusOK)
	if got.ID != f.ID || got.Status != string(db.FindingTriaged) {
		t.Fatalf("response = %+v", got)
	}
	for _, key := range []string{"verify_in_flight", "has_disclosure_draft", "disclosure_blocked", "vince", "akrites"} {
		if _, ok := got.Workflow[key]; !ok {
			t.Errorf("workflow missing %q: %v", key, got.Workflow)
		}
	}
	stored := reloadFinding(t, s, f.ID)
	if stored.Status != db.FindingTriaged {
		t.Fatalf("stored status = %q", stored.Status)
	}
	if w.Header().Get("ETag") != etagFor(stored.UpdatedAt) {
		t.Errorf("ETag = %q, want %q", w.Header().Get("ETag"), etagFor(stored.UpdatedAt))
	}
	var hist db.FindingHistory
	if err := s.DB.Where("finding_id = ? AND field = ?", f.ID, statusKey).Last(&hist).Error; err != nil {
		t.Fatal(err)
	}
	if hist.NewValue != string(db.FindingTriaged) || hist.By != "walter" || hist.Source != db.SourceAnalyst {
		t.Errorf("history = %+v", hist)
	}
}

// Prefer: return=representation answers the transition with the full
// FindingDetail instead of the slim row.
func TestUIFindingActionsStatusRepresentation(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := uiActSeed(t, s)

	req := operatorReq(t, http.MethodPost, uiActPath(f.ID, "status"), map[string]any{"status": "triaged"})
	req.Header.Set(uiPreferHeader, uiPreferFull)
	got := decodeUIJSON[map[string]any](t, serveUI(t, s, req), http.StatusOK)
	if got[statusKey] != string(db.FindingTriaged) {
		t.Fatalf("status = %v", got[statusKey])
	}
	for _, key := range []string{"workflow", "counts", "exports", "cwe_info"} {
		if _, ok := got[key]; !ok {
			t.Errorf("representation missing %q", key)
		}
	}
}

func TestUIFindingActionsStatusErrors(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := uiActSeed(t, s)

	cases := []struct {
		name  string
		body  any
		code  int
		ecode string
		field string
	}{
		{"missing", map[string]any{}, http.StatusUnprocessableEntity, uiCodeValidationFailed, "status"},
		{"unknown", map[string]any{"status": "bogus"}, http.StatusUnprocessableEntity, uiCodeValidationFailed, "status"},
		{"ready without draft", map[string]any{"status": "ready"}, http.StatusUnprocessableEntity, uiCodeValidationFailed, "status"},
		{"reject without verdict", map[string]any{"status": "rejected", "reason": "dup"}, http.StatusUnprocessableEntity, uiCodeValidationFailed, "verdict"},
		{"reject without reason", map[string]any{"status": "rejected", "verdict": "false_positive"}, http.StatusUnprocessableEntity, uiCodeValidationFailed, "reason"},
		{"malformed", "{", http.StatusBadRequest, uiCodeBadParam, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID, "status"), tc.body))
			body := requireUIError(t, w, tc.code, tc.ecode)
			if tc.field != "" && body.Fields[tc.field] == "" {
				t.Errorf("fields = %v, want %q", body.Fields, tc.field)
			}
		})
	}
	if reloadFinding(t, s, f.ID).Status != db.FindingEnriched {
		t.Error("a refused transition changed the status")
	}

	w := serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID+999, "status"), map[string]any{"status": "triaged"}))
	requireUIError(t, w, http.StatusNotFound, uiCodeNotFound)
}

func TestUIFindingActionsStatusReject(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := uiActSeed(t, s)

	w := serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID, "status"),
		map[string]any{"status": "rejected", "verdict": "false_positive", "reason": "sanitised upstream", "reviewer": "walter"}))
	got := decodeUIJSON[uiActStatusResponse](t, w, http.StatusOK)
	if got.Status != string(db.FindingRejected) {
		t.Fatalf("status = %q", got.Status)
	}
	reviews, err := db.ListFindingReviews(s.DB, f.ID)
	if err != nil || len(reviews) != 1 || reviews[0].Verdict != "false_positive" || reviews[0].Reviewer != "walter" {
		t.Fatalf("reviews = %+v, %v", reviews, err)
	}
}

func TestUIFindingActionsStatusIfMatch(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := uiActSeed(t, s)

	stale := operatorReq(t, http.MethodPost, uiActPath(f.ID, "status"), map[string]any{"status": "triaged"})
	stale.Header.Set("If-Match", `"2001-01-01T00:00:00Z"`)
	body := requireUIError(t, serveUI(t, s, stale), http.StatusConflict, uiCodeConflict)
	if body.Current["id"] == nil {
		t.Errorf("conflict must carry the current row: %+v", body)
	}

	fresh := operatorReq(t, http.MethodPost, uiActPath(f.ID, "status"), map[string]any{"status": "triaged"})
	fresh.Header.Set("If-Match", etagFor(reloadFinding(t, s, f.ID).UpdatedAt))
	decodeUIJSON[uiActStatusResponse](t, serveUI(t, s, fresh), http.StatusOK)
}

func TestUIFindingActionsStatusNonViable(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := uiActSeed(t, s)
	s.DB.Model(&db.Finding{}).Where("id = ?", f.ID).Updates(map[string]any{
		"production_viability": db.ProductionViabilityNonViable, "disclosure_draft": "draft",
	})
	w := serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID, "status"), map[string]any{"status": "ready"}))
	requireUIError(t, w, http.StatusPreconditionFailed, uiCodePreconditionFailed)
}

type uiActClaimBody struct {
	Code     string   `json:"code"`
	Contacts []string `json:"contacts"`
}

func TestUIFindingActionsStatusFederationClaim(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = testFederationSalt
	s.FederationPeers = []string{peerServer(t, http.StatusOK, `{"match":true,"contact":"peer@example.com"}`)}
	f := seedReadyFinding(t, s)

	w := serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID, "status"), map[string]any{"status": "reported"}))
	claim := decodeUIJSON[uiActClaimBody](t, w, http.StatusConflict)
	if claim.Code != uiCodeFederationClaimed || len(claim.Contacts) != 1 || claim.Contacts[0] == "" {
		t.Fatalf("claim = %+v (%s)", claim, w.Body)
	}
	if got := reloadFinding(t, s, f.ID); got.Status != db.FindingReady || got.FederationClaimContacts == "" {
		t.Fatalf("claimed finding = %q / %q", got.Status, got.FederationClaimContacts)
	}

	// The recorded claim is the acknowledgement: repeating goes through.
	w = serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID, "status"), map[string]any{"status": "reported"}))
	if got := decodeUIJSON[uiActStatusResponse](t, w, http.StatusOK); got.Status != string(db.FindingReported) {
		t.Fatalf("status = %q", got.Status)
	}
}

// ---------------------------------------------------------------- skill actions

type uiActEnqueued struct {
	ScanID uint `json:"scan_id"`
}

func TestUIFindingActionsVerifyQueuesFeedbackAndDedups(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedVerificationFeedback(t, s)

	w := serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID, "actions/verify"),
		map[string]any{"feedback": "  check the first-party parser\n", "model": ModelTierMid}))
	got := decodeUIJSON[uiActEnqueued](t, w, http.StatusAccepted)
	scans := uiActQueuedScans(t, s, f.ID, verifySkillName)
	if len(scans) != 1 || scans[0].ID != got.ScanID {
		t.Fatalf("queued = %+v, response %d", scans, got.ScanID)
	}
	sc := scans[0]
	if sc.FindingID == nil || *sc.FindingID != f.ID || sc.RepositoryID != f.RepositoryID ||
		sc.VerificationFeedback != "check the first-party parser" || sc.Kind != worker.JobSkill {
		t.Fatalf("scan opts = %+v", sc)
	}
	if want := resolveModelPreference(s.DB, ModelTierMid, s.DefaultModel()); sc.Model != want {
		t.Errorf("model = %q, want %q", sc.Model, want)
	}
	assertQueuedJobCount(t, s, 1)

	w = serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID, "actions/verify"), nil))
	body := requireUIError(t, w, http.StatusConflict, uiCodeInFlight)
	if body.ScanID != got.ScanID {
		t.Errorf("in_flight scan_id = %d, want %d", body.ScanID, got.ScanID)
	}
	assertQueuedJobCount(t, s, 1)
}

func TestUIFindingActionsLaunchers(t *testing.T) {
	cases := []struct {
		action, skill string
		dedup         bool
	}{
		{"critic", criticSkillName, true},
		{"disclose", discloseSkillName, true},
		{"public-issue", publicIssueSkillName, false},
		{"patch", patchSkillName, false},
		{"mitigate", mitigateSkillName, false},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			f := uiActSeed(t, s)
			sk := uiActSkill(t, s, tc.skill)
			for range 2 {
				serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID, "actions/"+tc.action), map[string]any{}))
			}
			scans := uiActQueuedScans(t, s, f.ID, tc.skill)
			want := 2
			if tc.dedup {
				want = 1
			}
			if len(scans) != want {
				t.Fatalf("queued %s scans = %d, want %d", tc.skill, len(scans), want)
			}
			if scans[0].SkillID == nil || *scans[0].SkillID != sk.ID || *scans[0].FindingID != f.ID {
				t.Errorf("scan opts = %+v", scans[0])
			}
			assertQueuedJobCount(t, s, want)
		})
	}
}

func TestUIFindingActionsReattack(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := uiActSeed(t, s)
	uiActSkill(t, s, reattackSkillName)

	w := serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID, "actions/reattack"), nil))
	requireUIError(t, w, http.StatusPreconditionFailed, uiCodePreconditionFailed)

	patch := db.Scan{RepositoryID: f.RepositoryID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: patchSkillName, FindingID: &f.ID}
	s.DB.Create(&patch)
	attempt := db.RemediationAttempt{FindingID: f.ID, PatchScanID: patch.ID, Attempt: 1, Patch: "diff", BaseCommit: "deadbeef"}
	s.DB.Create(&attempt)

	w = serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID, "actions/reattack"), nil))
	got := decodeUIJSON[uiActEnqueued](t, w, http.StatusAccepted)
	var sc db.Scan
	s.DB.First(&sc, got.ScanID)
	if sc.RemediationAttemptID == nil || *sc.RemediationAttemptID != attempt.ID || sc.Ref != "deadbeef" {
		t.Fatalf("reattack opts = %+v", sc)
	}
}

func TestUIFindingActionsErrors(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := uiActSeed(t, s)

	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID, "actions/explode"), nil)),
		http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID+999, "actions/critic"), nil)),
		http.StatusNotFound, uiCodeNotFound)
	// Skill not installed.
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID, "actions/critic"), nil)),
		http.StatusPreconditionFailed, uiCodePreconditionFailed)
	// Feedback is verify-only.
	uiActSkill(t, s, criticSkillName)
	body := requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID, "actions/critic"),
		map[string]any{"feedback": "x"})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	if body.Fields["feedback"] == "" {
		t.Errorf("fields = %v", body.Fields)
	}
	// A NON_VIABLE finding cannot be disclosed.
	uiActSkill(t, s, discloseSkillName)
	s.DB.Model(&db.Finding{}).Where("id = ?", f.ID).Update("production_viability", db.ProductionViabilityNonViable)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID, "actions/disclose"), nil)),
		http.StatusPreconditionFailed, uiCodePreconditionFailed)
	assertQueuedJobCount(t, s, 0)
}

// ---------------------------------------------------------------- exposure

type uiActBatch struct {
	ScanIDs []uint `json:"scan_ids"`
	Queued  int    `json:"queued"`
	Skipped int    `json:"skipped"`
	Message string `json:"message"`
}

func TestUIFindingActionsExposure(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := uiActSeed(t, s)

	// No skill yet.
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID, "actions/exposure"), nil)),
		http.StatusPreconditionFailed, uiCodePreconditionFailed)
	uiActSkill(t, s, exposureSkillName)
	// No dependents recorded.
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID, "actions/exposure"), nil)),
		http.StatusUnprocessableEntity, uiCodeValidationFailed)

	withURL := db.Dependent{RepositoryID: f.RepositoryID, Name: "app", RepositoryURL: "https://github.com/acme/app", DependentRepos: 5}
	noURL := db.Dependent{RepositoryID: f.RepositoryID, Name: "orphan", DependentRepos: 1}
	s.DB.Create(&withURL)
	s.DB.Create(&noURL)

	w := serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID, "actions/exposure"), map[string]any{"model": ModelTierMid}))
	got := decodeUIJSON[uiActBatch](t, w, http.StatusAccepted)
	if got.Queued != 1 || got.Skipped != 1 || len(got.ScanIDs) != 1 || got.Message == "" {
		t.Fatalf("batch = %+v", got)
	}
	var sc db.Scan
	s.DB.First(&sc, got.ScanIDs[0])
	if sc.Kind != worker.JobExposure || sc.DependentID == nil || *sc.DependentID != withURL.ID || *sc.FindingID != f.ID {
		t.Fatalf("exposure opts = %+v", sc)
	}
	assertQueuedJobCount(t, s, 1)
	var skipped db.FindingDependent
	if err := s.DB.Where("finding_id = ? AND dependent_id = ?", f.ID, noURL.ID).First(&skipped).Error; err != nil ||
		skipped.Status != db.ExposureUnderInvestigation {
		t.Errorf("skipped dependent = %+v, %v", skipped, err)
	}
}

// ---------------------------------------------------------------- validate-fix

type uiActValidateFix struct {
	ScanID        uint   `json:"scan_id"`
	VerifyScanIDs []uint `json:"verify_scan_ids"`
}

func TestUIFindingActionsValidateFix(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "fixme")
	deep := uiActSkill(t, s, deepDiveSkillName)
	uiActSkill(t, s, verifySkillName)
	baseline := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillID: &deep.ID, SkillName: deepDiveSkillName, SubPath: "lib"}
	s.DB.Create(&baseline)
	f := seedUIFinding(t, s.DB, baseline, "Overflow", db.FindingTriaged)

	path := uiActPath(f.ID, "actions/validate-fix")
	for name, body := range map[string]map[string]any{
		"missing ref": {},
		"bad ref":     {"ref": "--upload-pack=x"},
	} {
		t.Run(name, func(t *testing.T) {
			got := requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, body)),
				http.StatusUnprocessableEntity, uiCodeValidationFailed)
			if got.Fields["ref"] == "" {
				t.Errorf("fields = %v", got.Fields)
			}
		})
	}
	other := seedUIFinding(t, s.DB, seedUIScan(t, s.DB, seedUIRepo(t, s.DB, "elsewhere"), db.ScanDone, deepDiveSkillName), "Other", db.FindingNew)
	got := requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]any{"ref": "fix-1", "finding_ids": []uint{f.ID, other.ID}})),
		http.StatusUnprocessableEntity, uiCodeValidationFailed)
	if got.Fields["finding_ids"] == "" {
		t.Errorf("fields = %v", got.Fields)
	}
	assertQueuedJobCount(t, s, 0)

	res := decodeUIJSON[uiActValidateFix](t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]any{"ref": " fix-1 "})), http.StatusAccepted)
	var anchor db.Scan
	s.DB.First(&anchor, res.ScanID)
	if anchor.Ref != "fix-1" || anchor.BaselineScanID == nil || *anchor.BaselineScanID != baseline.ID ||
		anchor.SkillID == nil || *anchor.SkillID != deep.ID || anchor.SubPath != "lib" {
		t.Fatalf("anchor opts = %+v", anchor)
	}
	if len(res.VerifyScanIDs) != 1 {
		t.Fatalf("verify scans = %v", res.VerifyScanIDs)
	}
	var verify db.Scan
	s.DB.First(&verify, res.VerifyScanIDs[0])
	if verify.SkillName != verifySkillName || verify.Ref != "fix-1" || verify.FindingID == nil || *verify.FindingID != f.ID {
		t.Fatalf("verify opts = %+v", verify)
	}
	assertQueuedJobCount(t, s, 2)

	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(f.ID+999, "actions/validate-fix"), map[string]any{"ref": "fix-1"})),
		http.StatusNotFound, uiCodeNotFound)
}

// ---------------------------------------------------------------- conversations

type uiActConversation struct {
	ID        uint   `json:"id"`
	FindingID *uint  `json:"finding_id"`
	Title     string `json:"title"`
	Messages  []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
	Back struct {
		RepositoryID uint  `json:"repository_id"`
		FindingID    *uint `json:"finding_id"`
	} `json:"back"`
}

func TestUIFindingActionsConversations(t *testing.T) {
	s, done, stub := chatServer(t)
	defer done()
	f := uiActSeed(t, s)
	path := uiActPath(f.ID, "conversations")

	if rows := decodeUIJSON[[]uiActConversation](t, serveUI(t, s, operatorReq(t, http.MethodGet, path, nil)), http.StatusOK); len(rows) != 0 {
		t.Fatalf("conversations = %+v", rows)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]any{"message": "  "})),
		http.StatusUnprocessableEntity, uiCodeValidationFailed)

	w := serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]any{"message": "Is this reachable?"}))
	conv := decodeUIJSON[uiActConversation](t, w, http.StatusCreated)
	if conv.FindingID == nil || *conv.FindingID != f.ID || conv.Back.RepositoryID != f.RepositoryID || conv.Title == "" {
		t.Fatalf("conversation = %+v", conv)
	}
	if len(conv.Messages) == 0 || conv.Messages[0].Role != db.ChatRoleUser || conv.Messages[0].Content != "Is this reachable?" {
		t.Fatalf("messages = %+v", conv.Messages)
	}
	if stub.gotMsg != "Is this reachable?" {
		t.Errorf("turn ran with %q", stub.gotMsg)
	}
	rows := decodeUIJSON[[]uiActConversation](t, serveUI(t, s, operatorReq(t, http.MethodGet, path, nil)), http.StatusOK)
	if len(rows) != 1 || rows[0].ID != conv.ID {
		t.Fatalf("conversations = %+v", rows)
	}

	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, uiActPath(f.ID+999, "conversations"), nil)),
		http.StatusNotFound, uiCodeNotFound)
	s.chatRunner = nil
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]any{"message": "hi"})),
		http.StatusServiceUnavailable, uiCodeUnavailable)
}
