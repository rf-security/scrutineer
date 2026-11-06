package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"scrutineer/internal/akrites"
	"scrutineer/internal/db"
	"scrutineer/internal/vince"
)

// Tests for the /api/v1/ui VINCE and Akrites endpoints (WP-API-2). The
// recipients are local httptest servers; nothing leaves the host.

// uiActJSONForm turns a form into the JSON object the SPA posts: single
// values as strings, repeated values as arrays.
func uiActJSONForm(form url.Values) map[string]any {
	out := map[string]any{}
	for k, v := range form {
		if len(v) == 1 {
			out[k] = v[0]
		} else {
			out[k] = v
		}
	}
	return out
}

func uiActVINCEServer(t *testing.T, status int, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

type uiActVINCEView struct {
	Eligible   bool           `json:"eligible"`
	Report     map[string]any `json:"report"`
	Attachment struct {
		Choice      string `json:"choice"`
		GeneratedAt string `json:"generated_at"`
		SHA256      string `json:"sha256"`
	} `json:"attachment"`
	AttachmentOptions []map[string]any `json:"attachment_options"`
	Sources           struct {
		Packages   []map[string]any `json:"packages"`
		References []map[string]any `json:"references"`
	} `json:"sources"`
	Confirmations []string         `json:"confirmations"`
	Submissions   []map[string]any `json:"submissions"`
}

func TestUIFindingDisclosureVINCEPreview(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	ctx := seedVINCEFinding(t, s)
	path := uiActPath(ctx.Finding.ID, "vince")

	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, path, nil)), http.StatusNotFound, uiCodeNotFound)

	srv, _ := uiActVINCEServer(t, http.StatusCreated, `{}`)
	s.VINCE = vince.Config{BaseURL: srv.URL, APIKey: "secret"}
	view := decodeUIJSON[uiActVINCEView](t, serveUI(t, s, operatorReq(t, http.MethodGet, path+"?attachment=report", nil)), http.StatusOK)
	if !view.Eligible || view.Report["product_name"] != "widget" || view.Report["vendor_name"] != "acme" {
		t.Fatalf("report = %+v", view.Report)
	}
	if _, ok := view.Report["coord_status"].([]any); !ok {
		t.Errorf("coord_status must be an array: %#v", view.Report["coord_status"])
	}
	if view.Attachment.Choice != vinceAttachmentReport || view.Attachment.SHA256 == "" || view.Attachment.GeneratedAt == "" {
		t.Errorf("attachment = %+v", view.Attachment)
	}
	if len(view.AttachmentOptions) != 3 || len(view.Sources.Packages) != 1 || len(view.Sources.References) != 1 || len(view.Confirmations) != 5 {
		t.Errorf("view = %+v", view)
	}

	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, path+"?package_id=999", nil)),
		http.StatusUnprocessableEntity, uiCodeValidationFailed)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, uiActPath(ctx.Finding.ID+999, "vince"), nil)),
		http.StatusNotFound, uiCodeNotFound)
	s.DB.Model(&db.Finding{}).Where("id = ?", ctx.Finding.ID).Update("disclosure_draft", "")
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, path, nil)), http.StatusConflict, uiCodePreconditionFailed)
}

type uiActSubmitResult struct {
	Submission struct {
		ID         uint   `json:"id"`
		Channel    string `json:"channel"`
		ExternalID string `json:"external_id"`
		Status     string `json:"status"`
	} `json:"submission"`
	ReportsURL string `json:"reports_url"`
}

func TestUIFindingDisclosureVINCESubmit(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	ctx := seedVINCEFinding(t, s)
	srv, requests := uiActVINCEServer(t, http.StatusCreated, `{"vrf_id":"VRF#26-07-ABCDE"}`)
	s.VINCE = vince.Config{BaseURL: srv.URL, APIKey: "secret"}
	path := uiActPath(ctx.Finding.ID, "vince")

	// Missing confirmations: 422 with per-field errors, nothing sent.
	invalid := uiActJSONForm(validVINCEWebForm())
	delete(invalid, "confirm_recipient")
	body := requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, invalid)),
		http.StatusUnprocessableEntity, uiCodeValidationFailed)
	if body.Fields["confirm_recipient"] == "" {
		t.Errorf("fields = %v", body.Fields)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]any{"contact_name": map[string]any{}})),
		http.StatusBadRequest, uiCodeBadParam)
	if requests.Load() != 0 {
		t.Fatalf("VINCE requests = %d before a valid submit", requests.Load())
	}

	form := uiActJSONForm(validVINCEWebForm())
	form["confirm_recipient"] = true // booleans are the checkbox value
	got := decodeUIJSON[uiActSubmitResult](t, serveUI(t, s, operatorReq(t, http.MethodPost, path, form)), http.StatusOK)
	if got.Submission.ExternalID != "VRF#26-07-ABCDE" || got.Submission.Channel != db.DisclosureChannelVINCE || got.ReportsURL == "" {
		t.Fatalf("result = %+v", got)
	}
	if reloadFinding(t, s, ctx.Finding.ID).Status != db.FindingReported {
		t.Error("a VINCE submission must move the finding to reported")
	}

	// A second submit needs resend.
	body = requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, form)),
		http.StatusUnprocessableEntity, uiCodeValidationFailed)
	if body.Fields["resend"] == "" {
		t.Errorf("fields = %v", body.Fields)
	}
	if requests.Load() != 1 {
		t.Errorf("VINCE requests = %d, want 1", requests.Load())
	}
}

func TestUIFindingDisclosureVINCEUpstreamAndClaim(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	ctx := seedVINCEFinding(t, s)
	srv, _ := uiActVINCEServer(t, http.StatusUnauthorized, `{}`)
	s.VINCE = vince.Config{BaseURL: srv.URL, APIKey: "secret"}
	path := uiActPath(ctx.Finding.ID, "vince")

	// VINCE's 401 is an upstream failure, never the SPA's own 401.
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, uiActJSONForm(validVINCEWebForm()))),
		http.StatusBadGateway, uiCodeNetwork)

	s.FederationSalt = testFederationSalt
	s.FederationPeers = []string{peerServer(t, http.StatusOK, `{"match":true,"contact":"peer@example.com"}`)}
	w := serveUI(t, s, operatorReq(t, http.MethodPost, path, uiActJSONForm(validVINCEWebForm())))
	claim := decodeUIJSON[uiActClaimBody](t, w, http.StatusConflict)
	if claim.Code != uiCodeFederationClaimed || len(claim.Contacts) != 1 {
		t.Fatalf("claim = %+v", claim)
	}

	s.VINCE = vince.Config{}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, uiActJSONForm(validVINCEWebForm()))),
		http.StatusNotFound, uiCodeNotFound)
}

func uiActAkrites(t *testing.T, s *Server, status int, body string) *atomic.Int32 {
	t.Helper()
	var posts atomic.Int32
	intake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(intake.Close)
	s.Akrites = akrites.Config{BaseURL: intake.URL, SubmissionToken: "private-token"}
	s.akritesHTTPClient = intake.Client()
	return &posts
}

type uiActAkritesView struct {
	ShowForm    bool             `json:"show_form"`
	Endpoint    string           `json:"endpoint"`
	Report      map[string]any   `json:"report"`
	Submissions []map[string]any `json:"submissions"`
}

func TestUIFindingDisclosureAkrites(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	ctx := seedVINCEFinding(t, s)
	path := uiActPath(ctx.Finding.ID, "akrites")

	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, path, nil)), http.StatusNotFound, uiCodeNotFound)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]any{})), http.StatusNotFound, uiCodeNotFound)

	posts := uiActAkrites(t, s, http.StatusAccepted, `{"receipt":"SUB-1"}`)
	view := decodeUIJSON[uiActAkritesView](t, serveUI(t, s, operatorReq(t, http.MethodGet, path, nil)), http.StatusOK)
	if !view.ShowForm || view.Endpoint == "" || view.Report["raw"] != ctx.Finding.DisclosureDraft ||
		view.Report["symbol_file"] != "cmd/run.go" || view.Report["symbol_line"] != "42" {
		t.Fatalf("view = %+v", view)
	}

	form := uiActJSONForm(akritesForm(view.Endpoint))
	delete(form, "confirm")
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, form)), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	if posts.Load() != 0 {
		t.Fatalf("intake posts = %d before confirmation", posts.Load())
	}

	form["confirm"] = true
	got := decodeUIJSON[uiActSubmitResult](t, serveUI(t, s, operatorReq(t, http.MethodPost, path, form)), http.StatusOK)
	if got.Submission.ExternalID != "SUB-1" || got.Submission.Channel != db.DisclosureChannelAkrites || got.Submission.Status != "queued" {
		t.Fatalf("result = %+v", got)
	}
	view = decodeUIJSON[uiActAkritesView](t, serveUI(t, s, operatorReq(t, http.MethodGet, path, nil)), http.StatusOK)
	if len(view.Submissions) != 1 {
		t.Errorf("submissions = %+v", view.Submissions)
	}

	s.DB.Model(&db.Finding{}).Where("id = ?", ctx.Finding.ID).Update("status", db.FindingFixed)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, form)), http.StatusConflict, uiCodePreconditionFailed)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, uiActPath(ctx.Finding.ID+999, "akrites"), nil)),
		http.StatusNotFound, uiCodeNotFound)
}

func TestUIFindingDisclosureAkritesUpstream(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	ctx := seedVINCEFinding(t, s)
	uiActAkrites(t, s, http.StatusInternalServerError, `{}`)
	endpoint, _ := s.Akrites.Endpoint()
	w := serveUI(t, s, operatorReq(t, http.MethodPost, uiActPath(ctx.Finding.ID, "akrites"), uiActJSONForm(akritesForm(endpoint))))
	// A 500 from intake is ambiguous: the reservation is kept as uncertain.
	got := decodeUIJSON[uiActSubmitResult](t, w, http.StatusBadGateway)
	if got.Submission.ID == 0 || got.Submission.Status != "uncertain" {
		t.Fatalf("kept submission = %+v (%s)", got.Submission, w.Body)
	}
	requireUIError(t, w, http.StatusBadGateway, uiCodeNetwork)
}
