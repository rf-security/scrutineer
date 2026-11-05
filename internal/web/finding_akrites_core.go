package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/git-pkgs/purl"

	"scrutineer/internal/akrites"
	"scrutineer/internal/db"
)

// The Akrites preview and submission shared by the HTML pages
// (findingAkritesPreview, findingAkritesSubmit) and GET/POST
// /api/v1/ui/findings/{id}/akrites. Like VINCE, the submission reads r.Form.

// akritesPreview builds the preview page for ctx. A non-zero status
// (404/409/500) comes with a plain message.
func (s *Server) akritesPreview(ctx disclosureFindingContext) (akritesPage, int, string) {
	page := akritesPage{Finding: ctx.Finding}
	page.Endpoint, _ = s.Akrites.Endpoint()
	var err error
	if page.Submissions, err = db.FindingDisclosureSubmissions(s.DB, ctx.Finding.ID, db.DisclosureChannelAkrites); err != nil {
		return page, http.StatusInternalServerError, "could not load Akrites submissions"
	}
	// Saved submissions stay readable after the token is removed; only new
	// submissions need it.
	if len(page.Submissions) == 0 && !s.Akrites.Enabled() {
		return page, http.StatusNotFound, "Akrites is not configured"
	}
	eligibility := akritesEligibility(ctx)
	if eligibility != nil && len(page.Submissions) == 0 {
		return page, http.StatusConflict, eligibility.Error()
	}
	if eligibility != nil {
		page.Error = eligibility.Error()
	}
	if page.ShowForm = s.Akrites.Enabled() && eligibility == nil; page.ShowForm {
		page.Disclosure = ctx.Finding.DisclosureDraft
		page.Exploit = strings.TrimSpace(ctx.Finding.Reach + "\n\n" + ctx.Finding.Validation)
		page.Report = akrites.Report{
			Software:       ctx.Repository.Name,
			AffectedSymbol: akritesSymbol(ctx.Finding),
			PackageRepoURL: ctx.Repository.URL, DiscoveryMethod: "ai-assisted",
			Email: s.Akrites.Email, Notify: "off",
		}
		packages, err := findingAdvisoryPackages(s.DB, ctx.Finding, nil)
		if err != nil {
			return page, http.StatusInternalServerError, "could not load affected packages"
		}
		if len(packages) == 1 {
			pkg := packages[0]
			page.Report.Software, page.Report.PURL = pkg.Name, pkg.PURL
			// Intake derives the ecosystem from a package URL, and otherwise
			// expects an OSV ecosystem name rather than the stored PURL type.
			if pkg.PURL == "" {
				page.Report.Ecosystem, _ = purl.PURLTypeToOSV(db.EcosystemType("", pkg.Ecosystem))
			}
		}
	}
	return page, 0, ""
}

// akritesSubmitOutcome is the result of one Akrites submission. When Page is
// set the form is re-rendered with Status; otherwise a non-submitted Kind is
// a plain-text error. Submission is the stored row once one exists.
type akritesSubmitOutcome struct {
	Kind       disclosureOutcomeKind
	Status     int
	Message    string
	Page       *akritesPage
	Claims     string
	Submission *db.DisclosureSubmission
}

// submitAkrites validates r.Form against ctx and submits the report. The
// caller holds vinceSubmitMu.
func (s *Server) submitAkrites(r *http.Request, ctx disclosureFindingContext) akritesSubmitOutcome {
	if err := akritesEligibility(ctx); err != nil {
		return akritesSubmitOutcome{Kind: disclosureIneligible, Status: http.StatusConflict, Message: err.Error()}
	}
	page := akritesPageFromForm(r, ctx.Finding)
	endpoint, err := s.Akrites.Endpoint()
	if err != nil {
		return akritesSubmitOutcome{Kind: disclosureInternal, Status: http.StatusInternalServerError, Message: err.Error()}
	}
	page.Endpoint, page.ShowForm = endpoint, true
	if page.Submissions, err = db.FindingDisclosureSubmissions(s.DB, ctx.Finding.ID, db.DisclosureChannelAkrites); err != nil {
		return akritesSubmitOutcome{Kind: disclosureInternal, Status: http.StatusInternalServerError, Message: "could not load Akrites submissions"}
	}
	fail := func(kind disclosureOutcomeKind, status int, message string) akritesSubmitOutcome {
		page.Error = message
		return akritesSubmitOutcome{Kind: kind, Status: status, Message: message, Page: &page}
	}
	if err := disclosureResendError(r, len(page.Submissions) > 0, "Akrites"); err != nil {
		return fail(disclosureInvalid, http.StatusUnprocessableEntity, err.Error())
	}
	if strings.TrimSpace(page.Disclosure) == "" {
		return fail(disclosureInvalid, http.StatusUnprocessableEntity, "a disclosure report is required")
	}
	body, err := page.Report.JSON()
	if err != nil {
		return fail(disclosureInvalid, http.StatusUnprocessableEntity, err.Error())
	}
	if r.FormValue("confirm") != "yes" || r.FormValue("endpoint") != endpoint {
		return fail(disclosureInvalid, http.StatusUnprocessableEntity, "confirm the recipient and reviewed report before submitting")
	}
	claims, err := s.claimPeerHold(r.Context(), ctx.Finding)
	if err != nil {
		return fail(disclosureClaimCheckFailed, http.StatusInternalServerError, "failed to check federation peers")
	}
	if claims != "" {
		out := fail(disclosureClaimed, http.StatusConflict, "A federation peer holds this finding: "+claims+". Coordinate through that contact before submitting again.")
		out.Claims = claims
		return out
	}
	// Reserve before POST so a crash leaves a record of a request that may
	// have reached Akrites.
	submission := db.DisclosureSubmission{
		FindingID: ctx.Finding.ID, Channel: db.DisclosureChannelAkrites, Endpoint: endpoint,
		Status: "uncertain", Actor: "analyst", Request: string(body),
	}
	if err := s.DB.Create(&submission).Error; err != nil {
		return fail(disclosureInternal, http.StatusInternalServerError, "could not record the submission before sending it")
	}
	client := akrites.Client{Config: s.Akrites, HTTPClient: s.akritesHTTPClient}
	receipt, err := client.Submit(r.Context(), page.Report)
	if err != nil {
		status, kept := s.akritesSubmitFailure(&page, &submission, err)
		out := akritesSubmitOutcome{Kind: disclosureUpstream, Status: status, Message: page.Error, Page: &page}
		if kept {
			out.Submission = &submission
		}
		return out
	}
	next := time.Now().Add(akritesPollInitial)
	// The receipt is saved on its own first so it survives a failure in the
	// outreach transaction below.
	saved := s.DB.Model(&submission).Updates(map[string]any{"external_id": receipt, "status": "queued", "next_poll_at": next})
	if saved.Error != nil || saved.RowsAffected != 1 {
		submission.ExternalID, submission.Status, submission.NextPollAt = receipt, "uncertain", nil
		page.Submissions = append([]db.DisclosureSubmission{submission}, page.Submissions...)
		page.ShowForm = false
		out := fail(disclosurePersistFailed, http.StatusInternalServerError, "Akrites accepted the report, but the receipt could not be saved. Record the receipt below and reconcile with Akrites. Do not resubmit.")
		out.Submission = &submission
		return out
	}
	submission.ExternalID, submission.Status, submission.NextPollAt = receipt, "queued", &next
	err = db.RecordDisclosureSubmission(s.DB, &submission, db.DisclosureOutreach{
		CommunicationChannel: db.DisclosureChannelAkrites,
		CommunicationActor:   "Akrites",
		CommunicationBody:    "Submitted a vulnerability report to Akrites. Receipt and intake status are available on the Akrites submission page.",
		AuditKind:            db.AuditEventDisclosureAkritesSubmitted, AuditSource: db.SourceAnalyst,
		AuditPayload: map[string]any{db.AuditKeyRepositoryID: ctx.Finding.RepositoryID, "attachments": len(page.Report.Attachments)},
	})
	if err != nil {
		page.Submissions = append([]db.DisclosureSubmission{submission}, page.Submissions...)
		page.ShowForm = false
		out := fail(disclosurePersistFailed, http.StatusInternalServerError, "The receipt is saved, but the finding status could not be updated. Review the finding manually. Do not resubmit.")
		out.Submission = &submission
		return out
	}
	return akritesSubmitOutcome{Kind: disclosureSubmitted, Submission: &submission}
}

// akritesSubmitFailure releases the reservation when intake definitely stored
// nothing, so the analyst's edits stay on the form for correction or a later
// retry. An ambiguous failure keeps the reservation as an uncertain record.
// It returns the response status and whether the reservation was kept.
func (s *Server) akritesSubmitFailure(page *akritesPage, submission *db.DisclosureSubmission, err error) (int, bool) {
	status := http.StatusBadGateway
	page.Error = err.Error()
	var response *akrites.ResponseError
	if errors.As(err, &response) && !response.Ambiguous {
		if response.Validation() {
			status = http.StatusUnprocessableEntity
		}
		if response.RetryAfter > 0 {
			page.Error += fmt.Sprintf(". Akrites asked for a delay; submit again after %s.", time.Now().Add(response.RetryAfter).UTC().Format(time.RFC3339))
		}
		if deleteErr := s.DB.Delete(submission).Error; deleteErr == nil {
			return status, false
		}
	}
	submission.LastError = err.Error()
	_ = s.DB.Save(submission).Error
	page.Submissions = append([]db.DisclosureSubmission{*submission}, page.Submissions...)
	page.ShowForm = false
	return status, true
}
