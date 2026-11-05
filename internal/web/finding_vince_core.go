package web

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/vince"
)

// The disclosure loader and the VINCE submission shared by the HTML form
// (findingVINCESubmit) and POST /api/v1/ui/findings/{id}/vince. The
// submission reads its input from r.Form, so the JSON handler adapts its body
// into url.Values and both paths run the same validated code.

// loadDisclosureContext loads a finding with everything the disclosure
// mappers read. A non-zero status (404/500) comes with a plain message.
func (s *Server) loadDisclosureContext(id uint) (disclosureFindingContext, int, string) {
	var out disclosureFindingContext
	if err := s.DB.First(&out.Finding, id).Error; err != nil {
		return out, http.StatusNotFound, "finding not found"
	}
	if err := s.DB.First(&out.Repository, out.Finding.RepositoryID).Error; err != nil {
		return out, http.StatusInternalServerError, "repository missing for finding"
	}
	if err := s.DB.First(&out.Scan, out.Finding.ScanID).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return out, http.StatusInternalServerError, "could not load finding scan"
	}
	queries := []struct {
		label string
		err   error
	}{
		{"packages", s.DB.Where("repository_id = ?", out.Finding.RepositoryID).Order("name").Find(&out.Packages).Error},
		{"references", s.DB.Where("finding_id = ?", out.Finding.ID).Order("id").Find(&out.References).Error},
		{"communications", s.DB.Where("finding_id = ?", out.Finding.ID).Order("at").Find(&out.Communications).Error},
		{"notes", s.DB.Where("finding_id = ?", out.Finding.ID).Order("created_at").Find(&out.Notes).Error},
	}
	for _, query := range queries {
		if query.err != nil {
			return out, http.StatusInternalServerError, "could not load finding " + query.label
		}
	}
	return out, 0, ""
}

// disclosureOutcomeKind classifies a submission result so each surface can
// pick its own response for it.
type disclosureOutcomeKind int

const (
	disclosureSubmitted disclosureOutcomeKind = iota
	// disclosureIneligible: the finding may not be sent (plain 409).
	disclosureIneligible
	// disclosureInternal: a load or bookkeeping failure before sending.
	disclosureInternal
	// disclosureClaimCheckFailed: the federation peers could not be asked.
	disclosureClaimCheckFailed
	// disclosureInvalid: field, confirmation or resend errors (422).
	disclosureInvalid
	// disclosureClaimed: a federation peer holds the finding (409).
	disclosureClaimed
	// disclosureUpstream: the recipient refused or failed the request.
	disclosureUpstream
	// disclosurePersistFailed: sent, but the result could not be saved.
	disclosurePersistFailed
)

// vinceSubmitOutcome is the result of one VINCE submission. Page is the form
// to re-render (nil for a plain-text error or success).
type vinceSubmitOutcome struct {
	Kind        disclosureOutcomeKind
	Status      int
	Message     string
	Page        *vincePageData
	FieldErrors vince.ValidationErrors
	Claims      string
	Ambiguous   bool
	// UpstreamKind is the vince.Client.Submit error kind on disclosureUpstream.
	UpstreamKind vince.ErrorKind
	VRFID        string
	ReportsURL   string
}

// submitVINCE validates r.Form against ctx and, when it passes, asks the
// federation peers and submits the report. The caller holds vinceSubmitMu so
// the eligibility re-check and POST are serialised.
func (s *Server) submitVINCE(r *http.Request, ctx disclosureFindingContext) vinceSubmitOutcome {
	if err := vinceEligibility(ctx.Finding, ctx.Notes); err != nil {
		return vinceSubmitOutcome{Kind: disclosureIneligible, Status: http.StatusConflict, Message: err.Error()}
	}

	report := vinceReportFromForm(r.Form)
	attachmentChoice := r.FormValue("attachment")
	confirmations := vinceConfirmations(r.Form)
	fieldErrors := vince.ValidationErrors{}
	packageID, selectedRefs, selectionErr := vinceSelections(r.Form, ctx)
	if selectionErr != nil {
		addVINCEError(fieldErrors, "selection", selectionErr.Error())
	}
	if err := report.Validate(); err != nil {
		var validation vince.ValidationErrors
		if errors.As(err, &validation) {
			mergeVINCEErrors(fieldErrors, validation)
		}
	}
	for field, confirmed := range confirmations {
		if !confirmed {
			addVINCEError(fieldErrors, field, "confirmation is required")
		}
	}

	attachment := s.vinceFormAttachment(r, ctx, attachmentChoice, fieldErrors)
	prior, err := db.FindingDisclosureSubmissions(s.DB, ctx.Finding.ID, db.DisclosureChannelVINCE)
	if err != nil {
		return vinceSubmitOutcome{Kind: disclosureInternal, Status: http.StatusInternalServerError, Message: "could not load VINCE submissions"}
	}
	if err := disclosureResendError(r, len(prior) > 0 || slices.ContainsFunc(ctx.References, vinceReference), "VINCE"); err != nil {
		addVINCEError(fieldErrors, "resend", err.Error())
	}

	if len(fieldErrors) > 0 {
		page := s.vincePage(ctx, report, packageID, selectedRefs, attachmentChoice,
			time.Now().UTC(), fieldErrors, confirmations)
		return vinceSubmitOutcome{Kind: disclosureInvalid, Status: http.StatusUnprocessableEntity,
			Message: "VINCE report has invalid or unresolved fields", Page: &page, FieldErrors: fieldErrors}
	}

	// Asked after the field errors, so an invalid form costs no peer round trip,
	// and before the submission, because that request is the outreach the
	// claim-check exists to deduplicate.
	claims, err := s.claimPeerHold(r.Context(), ctx.Finding)
	if err != nil {
		s.Log.Error("claim-check out", "finding", ctx.Finding.ID, "err", err)
		return vinceSubmitOutcome{Kind: disclosureClaimCheckFailed, Status: http.StatusInternalServerError, Message: "failed to check federation peers"}
	}
	if claims != "" {
		page := s.vincePage(ctx, report, packageID, selectedRefs, attachmentChoice,
			time.Now().UTC(), nil, confirmations)
		page.Error = "A federation peer already holds this finding: " + claims +
			". Coordinate through that contact, then submit again to send it anyway."
		return vinceSubmitOutcome{Kind: disclosureClaimed, Status: http.StatusConflict, Message: page.Error, Page: &page, Claims: claims}
	}

	client := vince.Client{Config: s.VINCE, HTTPClient: s.vinceHTTPClient}
	vrfID, err := client.Submit(r.Context(), report, attachment)
	if err != nil {
		submitErr, _ := vince.AsSubmitError(err)
		status := http.StatusBadGateway
		message := err.Error()
		ambiguous := false
		var kind vince.ErrorKind
		if submitErr != nil {
			kind = submitErr.Kind
			mergeVINCEErrors(fieldErrors, submitErr.FieldErrors)
			switch submitErr.Kind {
			case vince.ErrorValidation:
				status = http.StatusUnprocessableEntity
			case vince.ErrorAuth:
				status = http.StatusUnauthorized
			case vince.ErrorRateLimit:
				status = http.StatusTooManyRequests
			case vince.ErrorAmbiguous:
				ambiguous = true
			}
		}
		if ambiguous {
			recipient, _ := s.VINCE.Endpoint()
			if err := s.DB.Create(&db.DisclosureSubmission{
				FindingID: ctx.Finding.ID, Channel: db.DisclosureChannelVINCE, Endpoint: recipient,
				Status: "uncertain", LastError: message, Actor: "analyst", Request: vinceRequest(report, attachment),
			}).Error; err != nil {
				s.Log.Error("record uncertain VINCE submission", "finding", ctx.Finding.ID, "err", err)
			}
		}
		page := s.vincePage(ctx, report, packageID, selectedRefs, attachmentChoice,
			time.Now().UTC(), fieldErrors, confirmations)
		page.Error = message
		page.Ambiguous = ambiguous
		return vinceSubmitOutcome{Kind: disclosureUpstream, Status: status, Message: message, Page: &page,
			FieldErrors: fieldErrors, Ambiguous: ambiguous, UpstreamKind: kind}
	}

	reportsURL, _ := s.VINCE.ReportsURL()
	attachmentName := "none"
	if attachment != nil {
		attachmentName = attachment.Name
	}
	if err := s.persistVINCESubmission(ctx.Finding, vrfID, reportsURL, attachmentName, report, attachment); err != nil {
		page := s.vincePage(ctx, report, packageID, selectedRefs, attachmentChoice,
			time.Now().UTC(), nil, confirmations)
		page.Error = "VINCE returned " + vrfID + " but Scrutineer could not save the result. Record the ID and reconcile it manually. Do not submit the report again."
		page.ReconciliationVRFID = vrfID
		return vinceSubmitOutcome{Kind: disclosurePersistFailed, Status: http.StatusInternalServerError, Message: page.Error, Page: &page, VRFID: vrfID}
	}
	return vinceSubmitOutcome{Kind: disclosureSubmitted, VRFID: vrfID, ReportsURL: reportsURL}
}
