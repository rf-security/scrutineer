package web

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"scrutineer/internal/akrites"
	"scrutineer/internal/db"
	"scrutineer/internal/vince"
)

// JSON twins of the VINCE and Akrites disclosure pages (02 section 3.2
// #23-#25). The preview projections use the HTML form's field names, so the
// SPA posts the report object back with its edits; the submit handlers adapt
// that body into url.Values and run the same validated code as the forms
// (submitVINCE, submitAkrites).

const (
	uiActKeyReport      = "report"
	uiActKeySubmissions = "submissions"
	uiActKeyEndpoint    = "endpoint"
	uiActKeyFieldErrors = "field_errors"
	uiActFormYes        = "yes"
	uiActKeyPackages    = "packages"
)

// uiActionSubmission is the DisclosureSubmission projection (the same
// shape as WP-API-1's uiDisclosureSubmission; TODO(lead): keep one). Request and
// Response are never exposed: they carry the report and attachment as sent.
func uiActionSubmission(sub db.DisclosureSubmission) map[string]any {
	return map[string]any{
		"id": sub.ID, "channel": sub.Channel, uiActKeyEndpoint: sub.Endpoint, "external_id": sub.ExternalID,
		"url": sub.URL, uiActKeyStatus: sub.Status, "status_at": sub.StatusAt, "last_error": sub.LastError,
		"actor": sub.Actor, uiKeyCreatedAt: sub.CreatedAt, "updated_at": sub.UpdatedAt,
	}
}

func uiActionSubmissions(subs []db.DisclosureSubmission) []map[string]any {
	out := make([]map[string]any, len(subs))
	for i, sub := range subs {
		out[i] = uiActionSubmission(sub)
	}
	return out
}

// uiFormValues adapts a JSON object to the url.Values the disclosure forms
// post: strings and numbers as-is, arrays as repeated values, true as "yes"
// (the checkbox value), false and null as absent.
func uiFormValues(body map[string]any) (url.Values, error) {
	values := url.Values{}
	for key, raw := range body {
		items, isList := raw.([]any)
		if !isList {
			items = []any{raw}
		}
		for _, item := range items {
			switch v := item.(type) {
			case nil:
			case string:
				values.Add(key, v)
			case bool:
				if v {
					values.Add(key, uiActFormYes)
				}
			case float64:
				values.Add(key, strconv.FormatFloat(v, 'f', -1, 64))
			default:
				return nil, fmt.Errorf("field %q must be a string, number, boolean or array of those", key)
			}
		}
	}
	return values, nil
}

// uiFormRequest decodes the JSON body into url.Values and returns a clone of
// r whose Form/PostForm carry them, so r.FormValue reads the JSON fields.
func uiFormRequest(w http.ResponseWriter, r *http.Request, limit int64) (*http.Request, bool) {
	var body map[string]any
	if !decodeUIActionBody(w, r, &body, limit, false) {
		return nil, false
	}
	values, err := uiFormValues(body)
	if err != nil {
		uiBadParam(w, err.Error())
		return nil, false
	}
	form := r.Clone(r.Context())
	form.Form, form.PostForm = values, values
	return form, true
}

// uiDisclosureContext loads the {id} finding's disclosure context.
func (s *Server) uiDisclosureContext(w http.ResponseWriter, r *http.Request) (disclosureFindingContext, bool) {
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return disclosureFindingContext{}, false
	}
	ctx, status, msg := s.loadDisclosureContext(id)
	if status != 0 {
		writeUIError(w, status, "", msg, nil)
		return ctx, false
	}
	return ctx, true
}

// flattenVINCEErrors joins each field's messages for the envelope's fields.
func flattenVINCEErrors(errs vince.ValidationErrors) map[string]string {
	out := make(map[string]string, len(errs))
	for field, messages := range errs {
		out[field] = strings.Join(messages, "; ")
	}
	return out
}

// ---------------------------------------------------------------- VINCE (#23, #24)

// vinceConfirmationFields are the checkboxes a submission must carry as "yes".
var vinceConfirmationFields = []string{
	"confirm_recipient", "confirm_reporter", "confirm_choices", "confirm_attachment", "confirm_manual_review",
}

// uiVINCEReportForm is vince.Report keyed by the form field names
// vinceReportFromForm reads, so the object round-trips through a submit.
func uiVINCEReportForm(r vince.Report) map[string]any {
	coord := r.CoordinationStatus
	if coord == nil {
		coord = []string{}
	}
	return map[string]any{
		"contact_name": r.ContactName, "contact_org": r.ContactOrganization, "contact_email": r.ContactEmail,
		"reporter_pgp": r.ReporterPGP, "contact_phone": r.ContactPhone, "share_release": r.ShareRelease,
		"credit_release": r.CreditRelease, "coord_status": coord, "comm_attempt": r.CommunicationAttempt,
		"why_no_attempt": r.WhyNoAttempt, "please_explain": r.PleaseExplain, "vendor_name": r.VendorName,
		"multiplevendors": r.MultipleVendors, "other_vendors": r.OtherVendors, "first_contact": r.FirstContact,
		"vendor_communication": r.VendorCommunication, "product_name": r.ProductName,
		"product_version": r.ProductVersion, "ics_impact": r.ICSImpact, "ai_ml_system": r.AIMLSystem,
		"vul_description": r.VulnerabilityDescription, "vul_exploit": r.VulnerabilityExploit,
		"vul_impact": r.VulnerabilityImpact, "vul_discovery": r.VulnerabilityDiscovery,
		"vul_public": r.VulnerabilityPublic, "public_references": r.PublicReferences,
		"vul_exploited": r.VulnerabilityExploited, "exploit_references": r.ExploitReferences,
		"vul_disclose": r.VulnerabilityDisclose, "disclosure_plans": r.DisclosurePlans,
		"tracking": r.Tracking, "comments": r.Comments, "cisa_please": r.CISACoordination,
	}
}

// uiVINCEView is the VinceView projection of the preview page.
func uiVINCEView(p vincePageData) map[string]any {
	packages := make([]map[string]any, len(p.Packages))
	for i, pkg := range p.Packages {
		packages[i] = map[string]any{"id": pkg.ID, uiKeyName: pkg.Name, "ecosystem": pkg.Ecosystem}
	}
	refs := make([]map[string]any, len(p.References))
	for i, ref := range p.References {
		refs[i] = map[string]any{"id": ref.ID, "url": ref.URL, "tags": ref.Tags, "summary": ref.Summary, "vince": vinceReference(ref)}
	}
	selectedRefs := slices.Sorted(maps.Keys(p.SelectedReferences))
	if selectedRefs == nil {
		selectedRefs = []uint{}
	}
	options := make([]map[string]any, len(p.AttachmentOptions))
	selected := map[string]any{"choice": p.Attachment, "size": 0, "too_large": false,
		"generated_at": p.AttachmentGeneratedAt, "sha256": p.AttachmentSHA256}
	for i, o := range p.AttachmentOptions {
		contents := o.Contents
		if contents == nil {
			contents = []string{}
		}
		options[i] = map[string]any{"value": o.Value, "label": o.Label, uiKeyName: o.Name, "size": o.Size,
			"too_large": o.TooLarge, "contents": contents}
		if o.Value == p.Attachment {
			selected["size"], selected["too_large"], selected[uiKeyName] = o.Size, o.TooLarge, o.Name
		}
	}
	return map[string]any{
		"eligible": true, "reason": "",
		"sources":            map[string]any{uiActKeyPackages: packages, "references": refs},
		"selection":          map[string]any{"package_id": p.SelectedPackageID, "reference_id": selectedRefs},
		uiActKeyReport:       uiVINCEReportForm(p.Report),
		"attachment":         selected,
		"attachment_options": options,
		"recipient":          p.Recipient,
		"reports_url":        p.ReportsURL,
		"sent_before":        p.SentBefore,
		"confirmations":      vinceConfirmationFields,
		uiActKeySubmissions:  uiActionSubmissions(p.Prior),
		uiActKeyFieldErrors:  flattenVINCEErrors(p.Errors),
	}
}

// uiFindingVINCE is GET /ui/findings/{id}/vince: the prefilled report, the
// selectable packages/references and the attachment preview (whose
// generated_at and sha256 the submit must echo). ?attachment= previews
// another attachment choice (bundle, report or none).
func (s *Server) uiFindingVINCE(w http.ResponseWriter, r *http.Request) {
	if !s.VINCE.Enabled() {
		uiNotFound(w, "VINCE integration")
		return
	}
	ctx, ok := s.uiDisclosureContext(w, r)
	if !ok {
		return
	}
	if err := vinceEligibility(ctx.Finding, ctx.Notes); err != nil {
		writeUIError(w, http.StatusConflict, uiCodePreconditionFailed, err.Error(), nil)
		return
	}
	packageID, selectedRefs, err := vinceSelections(r.URL.Query(), ctx)
	if err != nil {
		writeUIFields(w, uiFieldErrors{"selection": err.Error()})
		return
	}
	report := s.mapVINCEReport(ctx, packageID, selectedRefs)
	choice := r.URL.Query().Get("attachment")
	if choice == "" {
		choice = vinceAttachmentBundle
	}
	page := s.vincePage(ctx, report, packageID, selectedRefs, choice, time.Now().UTC(), nil, nil)
	writeUIJSON(w, http.StatusOK, uiVINCEView(page))
}

// uiFindingVINCESubmit is POST /ui/findings/{id}/vince with the form's fields
// as a JSON object (the preview's report plus package_id, reference_id,
// attachment, attachment_generated_at, attachment_sha256, confirm_*, resend).
func (s *Server) uiFindingVINCESubmit(w http.ResponseWriter, r *http.Request) {
	if !s.VINCE.Enabled() {
		uiNotFound(w, "VINCE integration")
		return
	}
	form, ok := uiFormRequest(w, r, uiActionBodyMax)
	if !ok {
		return
	}
	// Serialised with the HTML form: see findingVINCESubmit.
	s.vinceSubmitMu.Lock()
	defer s.vinceSubmitMu.Unlock()
	ctx, ok := s.uiDisclosureContext(w, form)
	if !ok {
		return
	}
	out := s.submitVINCE(form, ctx)
	switch out.Kind {
	case disclosureSubmitted:
		s.publishFinding(ctx.Finding.ID, ctx.Finding.RepositoryID, uiChangeUpdated,
			uiActKeySubmissions, "references", "communications", uiActKeyStatus, "history")
		var sub db.DisclosureSubmission
		if err := s.DB.Where("finding_id = ? AND channel = ? AND external_id = ?",
			ctx.Finding.ID, db.DisclosureChannelVINCE, out.VRFID).Order("id desc").First(&sub).Error; err != nil {
			uiInternal(w, err)
			return
		}
		writeUIJSON(w, http.StatusOK, map[string]any{"submission": uiActionSubmission(sub), "reports_url": out.ReportsURL})
	case disclosureUpstream:
		if out.Ambiguous {
			s.publishFinding(ctx.Finding.ID, ctx.Finding.RepositoryID, uiChangeUpdated, uiActKeySubmissions)
		}
		writeVINCEUpstreamError(w, out)
	default:
		writeDisclosureOutcomeError(w, out.Kind, out.Status, out.Message, out.Claims,
			map[string]any{"reconciliation_vrf_id": out.VRFID}, out.FieldErrors)
	}
}

// writeVINCEUpstreamError maps a vince.Client.Submit failure. Only a
// validation refusal is the analyst's to fix (422); auth, rate limits and
// ambiguous or bad responses are upstream failures (502, with the kind), so
// the SPA never mistakes VINCE's 401 for its own session expiring.
func writeVINCEUpstreamError(w http.ResponseWriter, out vinceSubmitOutcome) {
	extra := map[string]any{"upstream": string(out.UpstreamKind), "ambiguous": out.Ambiguous}
	if len(out.FieldErrors) > 0 {
		extra["fields"] = flattenVINCEErrors(out.FieldErrors)
		extra[uiActKeyFieldErrors] = out.FieldErrors
	}
	if out.Status == http.StatusUnprocessableEntity {
		writeUIErrorExtra(w, http.StatusUnprocessableEntity, uiCodeValidationFailed, out.Message, extra)
		return
	}
	writeUIErrorExtra(w, http.StatusBadGateway, uiCodeNetwork, out.Message, extra)
}

// writeDisclosureOutcomeError maps the non-upstream failures every
// disclosure channel shares.
func writeDisclosureOutcomeError(w http.ResponseWriter, kind disclosureOutcomeKind, status int, msg, claims string,
	persistExtra map[string]any, fieldErrors vince.ValidationErrors,
) {
	switch kind {
	case disclosureIneligible:
		writeUIError(w, http.StatusConflict, uiCodePreconditionFailed, msg, nil)
	case disclosureInvalid:
		extra := map[string]any{}
		if len(fieldErrors) > 0 {
			extra["fields"] = flattenVINCEErrors(fieldErrors)
			extra[uiActKeyFieldErrors] = fieldErrors
		}
		writeUIErrorExtra(w, http.StatusUnprocessableEntity, uiCodeValidationFailed, msg, extra)
	case disclosureClaimed:
		writeUIErrorExtra(w, http.StatusConflict, uiCodeFederationClaimed, msg, map[string]any{uiActKeyContacts: uiClaimContacts(claims)})
	case disclosureClaimCheckFailed:
		writeUIError(w, http.StatusServiceUnavailable, uiCodeUnavailable, msg, nil)
	case disclosurePersistFailed:
		writeUIErrorExtra(w, http.StatusInternalServerError, uiCodeInternal, msg, persistExtra)
	default:
		writeUIError(w, status, "", msg, nil)
	}
}

// ---------------------------------------------------------------- Akrites (#25)

// uiAkritesReportForm is the Akrites form keyed by the field names
// akritesPageFromForm reads.
func uiAkritesReportForm(p akritesPage) map[string]any {
	symbol := akrites.Symbol{}
	if p.Report.AffectedSymbol != nil {
		symbol = *p.Report.AffectedSymbol
	}
	line := ""
	if symbol.Line != 0 {
		line = strconv.Itoa(symbol.Line)
	}
	return map[string]any{
		"software": p.Report.Software, "purl": p.Report.PURL, "ecosystem": p.Report.Ecosystem,
		"versions": strings.Join(p.Report.Versions, "\n"), "raw": p.Disclosure, "exploit": p.Exploit,
		"package_repo_url": p.Report.PackageRepoURL, "discovery_method": p.Report.DiscoveryMethod,
		"email": p.Report.Email, "notify": p.Report.Notify,
		"symbol_file": symbol.File, "symbol_function": symbol.Function, "symbol_line": line,
	}
}

// uiAkritesView is the AkritesView projection.
func uiAkritesView(p akritesPage) map[string]any {
	view := map[string]any{
		"show_form": p.ShowForm, uiActKeyEndpoint: p.Endpoint, "error": p.Error,
		uiActKeySubmissions: uiActionSubmissions(p.Submissions), uiActKeyReport: nil,
	}
	if p.ShowForm {
		view[uiActKeyReport] = uiAkritesReportForm(p)
	}
	return view
}

// uiFindingAkrites is GET /ui/findings/{id}/akrites: the prefilled report
// (when a submission is possible) and the earlier submissions.
func (s *Server) uiFindingAkrites(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.uiDisclosureContext(w, r)
	if !ok {
		return
	}
	page, status, msg := s.akritesPreview(ctx)
	switch status {
	case 0:
		writeUIJSON(w, http.StatusOK, uiAkritesView(page))
	case http.StatusConflict:
		writeUIError(w, status, uiCodePreconditionFailed, msg, nil)
	default:
		writeUIError(w, status, "", msg, nil)
	}
}

// uiFindingAkritesSubmit is POST /ui/findings/{id}/akrites with the form's
// fields as a JSON object (the preview's report plus confirm and endpoint,
// and resend when sending again).
func (s *Server) uiFindingAkritesSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.Akrites.Enabled() {
		uiNotFound(w, "Akrites integration")
		return
	}
	// JSON escaping can expand each byte, as URL encoding does for the form.
	const jsonEncodingExpansion = 3
	form, ok := uiFormRequest(w, r, jsonEncodingExpansion*akrites.MaxBodySize)
	if !ok {
		return
	}
	s.vinceSubmitMu.Lock()
	defer s.vinceSubmitMu.Unlock()
	ctx, ok := s.uiDisclosureContext(w, form)
	if !ok {
		return
	}
	out := s.submitAkrites(form, ctx)
	if out.Submission != nil {
		s.publishFinding(ctx.Finding.ID, ctx.Finding.RepositoryID, uiChangeUpdated, uiActKeySubmissions, "communications", uiActKeyStatus, "history")
	}
	var persist map[string]any
	if out.Submission != nil {
		persist = map[string]any{"submission": uiActionSubmission(*out.Submission)}
	}
	switch out.Kind {
	case disclosureSubmitted:
		writeUIJSON(w, http.StatusOK, map[string]any{"submission": uiActionSubmission(*out.Submission)})
	case disclosureUpstream:
		code := uiCodeNetwork
		status := http.StatusBadGateway
		if out.Status == http.StatusUnprocessableEntity {
			code, status = uiCodeValidationFailed, http.StatusUnprocessableEntity
		}
		writeUIErrorExtra(w, status, code, out.Message, persist)
	default:
		writeDisclosureOutcomeError(w, out.Kind, out.Status, out.Message, out.Claims, persist, nil)
	}
}
