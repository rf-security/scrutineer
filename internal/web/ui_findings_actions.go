package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/verification"
)

// registerUIFindingActionRoutes registers the finding status, action and disclosure routes of the /api/v1/ui surface
// (02-api-plan.md section 3.2 #12, #19-#21, #23-#27). Owned by WP-API-2: add handlers in this file (or
// siblings you own) with string-literal, method-qualified patterns relative to
// /api/v1, e.g. mux.HandleFunc("GET /ui/...", s.handler), and document each in
// openapi.yaml between the "# --- ui:finding-actions begin/end ---" markers.
// TestOpenAPICoversRegisteredAPIRoutes fails on any undocumented route.
func (s *Server) registerUIFindingActionRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /ui/findings/{id}/status", s.uiFindingStatus)
	mux.HandleFunc("POST /ui/findings/{id}/actions/exposure", s.uiFindingExposure)
	mux.HandleFunc("POST /ui/findings/{id}/actions/validate-fix", s.uiFindingValidateFix)
	mux.HandleFunc("POST /ui/findings/{id}/actions/{action}", s.uiFindingAction)
	mux.HandleFunc("GET /ui/findings/{id}/conversations", s.uiFindingConversations)
	mux.HandleFunc("POST /ui/findings/{id}/conversations", s.uiFindingConversationCreate)
	mux.HandleFunc("GET /ui/findings/{id}/vince", s.uiFindingVINCE)
	mux.HandleFunc("POST /ui/findings/{id}/vince", s.uiFindingVINCESubmit)
	mux.HandleFunc("GET /ui/findings/{id}/akrites", s.uiFindingAkrites)
	mux.HandleFunc("POST /ui/findings/{id}/akrites", s.uiFindingAkritesSubmit)
}

const (
	// uiActionBodyMax caps the JSON bodies of the action endpoints.
	uiActionBodyMax = 1 << 20

	uiActKeyStatus   = "status"
	uiActKeyFeedback = "feedback"
	uiActKeyMessage  = "message"
	uiActKeyContacts = "contacts"
	uiActFindingWhat = "finding"
	uiActKeyTitle    = "title"
)

// decodeUIActionBody decodes a JSON body into dst under limit bytes. An empty
// body is accepted when optional. A malformed body writes a 400.
func decodeUIActionBody(w http.ResponseWriter, r *http.Request, dst any, limit int64, optional bool) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	err := json.NewDecoder(r.Body).Decode(dst)
	if err == nil || (optional && errors.Is(err, io.EOF)) {
		return true
	}
	uiBadParam(w, "invalid JSON request body: "+err.Error())
	return false
}

// uiActionFinding loads the {id} finding, writing 400/404 on failure.
func (s *Server) uiActionFinding(w http.ResponseWriter, r *http.Request) (db.Finding, bool) {
	var f db.Finding
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return f, false
	}
	if err := s.DB.First(&f, id).Error; err != nil {
		uiDBError(w, err, uiActFindingWhat)
		return f, false
	}
	return f, true
}

// uiClaimContacts splits the recorded federation claim ("peer (contact), ...")
// into the envelope's contacts array.
func uiClaimContacts(claims string) []string {
	out := []string{}
	for c := range strings.SplitSeq(claims, ", ") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// uiActionFindingRow is the FindingRow projection of one finding.
func (s *Server) uiActionFindingRow(f db.Finding) map[string]any {
	return s.uiFindingRows([]db.Finding{f})[0]
}

// ---------------------------------------------------------------- workflow

// uiFindingActionWorkflow is the FindingWorkflow object: which skills are in
// flight (scan id or null) and the gates the finding page derives from it.
// TODO(lead): same object as WP-API-1's uiFindingWorkflow (#10); keep one
// after both merge.
func (s *Server) uiFindingActionWorkflow(f db.Finding) map[string]any {
	open := func(skill string, attemptID *uint) any {
		if sc, ok := s.openFindingSkillScanForAttempt(f.ID, skill, attemptID); ok {
			return sc.ID
		}
		return nil
	}
	var attemptID *uint
	if attempt, err := db.LatestRemediationAttempt(s.DB, f.ID); err == nil && attempt != nil {
		attemptID = &attempt.ID
	}
	repoID := f.RepositoryID
	if repoID == 0 {
		var scan db.Scan
		if s.DB.Select("id", "repository_id").First(&scan, f.ScanID).Error == nil {
			repoID = scan.RepositoryID
		}
	}
	hasDependents, err := repoHasDependents(s.DB, repoID)
	if err != nil {
		s.Log.Warn("count dependents", "repo", repoID, "err", err)
	}
	vinceReason := "VINCE API key is not configured"
	vinceReady := false
	if s.VINCE.Enabled() {
		var notes []db.FindingNote
		s.DB.Where("finding_id = ?", f.ID).Order("created_at desc").Find(&notes)
		if err := vinceEligibility(f, notes); err != nil {
			vinceReason = err.Error()
		} else {
			vinceReady, vinceReason = true, ""
		}
	}
	var akritesSubmissions int64
	s.DB.Model(&db.DisclosureSubmission{}).Where("finding_id = ? AND channel = ?", f.ID, db.DisclosureChannelAkrites).Count(&akritesSubmissions)
	return map[string]any{
		"verify_in_flight":     open(verifySkillName, nil),
		"critic_in_flight":     open(criticSkillName, nil),
		"disclose_in_flight":   open(discloseSkillName, nil),
		"reattack_in_flight":   open(reattackSkillName, attemptID),
		"has_dependents":       hasDependents,
		"has_disclosure_draft": strings.TrimSpace(f.DisclosureDraft) != "",
		"disclosure_blocked":   db.FindingDisclosureBlocked(f),
		"vince":                map[string]any{"ready": vinceReady, "reason": vinceReason},
		"akrites":              map[string]any{"enabled": s.Akrites.Enabled(), "has_submissions": akritesSubmissions > 0},
	}
}

// ---------------------------------------------------------------- #12 status

type uiFindingStatusBody struct {
	Status   string `json:"status"`
	Verdict  string `json:"verdict"`
	Reason   string `json:"reason"`
	Reviewer string `json:"reviewer"`
	By       string `json:"by"`
}

// uiFindingStatus is POST /ui/findings/{id}/status: the status transition of
// the finding page (applyFindingStatus) with JSON errors.
func (s *Server) uiFindingStatus(w http.ResponseWriter, r *http.Request) {
	f, ok := s.uiActionFinding(w, r)
	if !ok {
		return
	}
	var body uiFindingStatusBody
	if !decodeUIActionBody(w, r, &body, uiActionBodyMax, false) {
		return
	}
	if strings.TrimSpace(body.Status) == "" {
		writeUIFields(w, uiFieldErrors{uiActKeyStatus: "status is required"})
		return
	}
	if !checkIfMatch(w, r, f.UpdatedAt, s.uiActionFindingRow(f)) {
		return
	}
	in := findingStatusInput{
		Status:  db.FindingLifecycle(strings.TrimSpace(body.Status)),
		Verdict: body.Verdict, Reason: body.Reason, Reviewer: body.Reviewer, By: body.By,
	}
	if err := s.applyFindingStatus(r.Context(), f, in); err != nil {
		writeFindingStatusUIError(w, err)
		return
	}
	fields := []string{uiActKeyStatus, "history"}
	if in.Status == db.FindingRejected {
		fields = append(fields, "reviews")
	}
	s.publishFinding(f.ID, f.RepositoryID, uiChangeUpdated, fields...)
	if err := s.DB.First(&f, f.ID).Error; err != nil {
		uiDBError(w, err, uiActFindingWhat)
		return
	}
	row := s.uiActionFindingRow(f)
	row["workflow"] = s.uiFindingActionWorkflow(f)
	setETag(w, f.UpdatedAt)
	writeUIJSON(w, http.StatusOK, row)
}

// writeFindingStatusUIError maps an applyFindingStatus error.
func writeFindingStatusUIError(w http.ResponseWriter, err error) {
	var claim *federationClaimError
	switch {
	case errors.As(err, &claim):
		writeUIErrorExtra(w, http.StatusConflict, uiCodeFederationClaimed, err.Error(), map[string]any{uiActKeyContacts: uiClaimContacts(claim.Contacts)})
	case errors.Is(err, db.ErrInvalidFindingReview):
		field := "reason"
		if strings.Contains(err.Error(), "verdict") {
			field = "verdict"
		}
		writeUIFields(w, uiFieldErrors{field: err.Error()})
	case errors.Is(err, errFindingReadyNeedsDraft), errors.Is(err, errInvalidFindingStatus):
		writeUIFields(w, uiFieldErrors{uiActKeyStatus: err.Error()})
	case errors.Is(err, db.ErrFindingNonViable):
		writeUIError(w, http.StatusPreconditionFailed, uiCodePreconditionFailed, err.Error(), nil)
	case errors.Is(err, errFederationClaimCheck), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		writeUIError(w, http.StatusServiceUnavailable, uiCodeUnavailable, err.Error(), nil)
	default:
		uiInternal(w, err)
	}
}

// ---------------------------------------------------------------- #19 skill actions

// uiFindingActionSkill is the skill behind one action and whether its launch
// is deduplicated against an open scan.
type uiFindingActionSkill struct {
	skill    string
	skipOpen bool
}

var uiFindingActionSkills = map[string]uiFindingActionSkill{
	"verify":       {verifySkillName, true},
	"critic":       {criticSkillName, true},
	"disclose":     {discloseSkillName, true},
	"public-issue": {publicIssueSkillName, false},
	"patch":        {patchSkillName, false},
	"reattack":     {reattackSkillName, true},
	"mitigate":     {mitigateSkillName, false},
}

type uiFindingActionBody struct {
	Model    string `json:"model"`
	Feedback string `json:"feedback"`
}

// uiFindingAction is POST /ui/findings/{id}/actions/{action}: one of the
// finding page's skill buttons. 202 {scan_id}; an open scan of a deduplicated
// skill is 409 in_flight {scan_id}.
func (s *Server) uiFindingAction(w http.ResponseWriter, r *http.Request) {
	action, known := uiFindingActionSkills[r.PathValue("action")]
	if !known {
		uiBadParam(w, "unknown action "+r.PathValue("action"))
		return
	}
	f, ok := s.uiActionFinding(w, r)
	if !ok {
		return
	}
	var body uiFindingActionBody
	if !decodeUIActionBody(w, r, &body, uiActionBodyMax, true) {
		return
	}
	if body.Feedback != "" && action.skill != verifySkillName {
		writeUIFields(w, uiFieldErrors{uiActKeyFeedback: "feedback is only accepted by verify"})
		return
	}
	feedback, err := verification.NormalizeFeedback(body.Feedback)
	if err != nil {
		writeUIFields(w, uiFieldErrors{uiActKeyFeedback: err.Error()})
		return
	}
	res, err := s.enqueueFindingSkillAction(r.Context(), f, findingSkillLaunch{
		Skill: action.skill, Model: body.Model, Feedback: feedback, SkipOpen: action.skipOpen,
	})
	if err != nil {
		s.writeFindingSkillUIError(w, f.ID, err)
		return
	}
	if res.Existing {
		writeUIErrorExtra(w, http.StatusConflict, uiCodeInFlight, action.skill+" already queued or running",
			map[string]any{uiEventScanIDKey: res.ScanID})
		return
	}
	enqueueResult(w, res.ScanID)
}

// writeFindingSkillUIError maps an enqueueFindingSkillAction error.
func (s *Server) writeFindingSkillUIError(w http.ResponseWriter, findingID uint, err error) {
	var missing findingSkillMissingError
	var precondition findingSkillPreconditionError
	switch {
	case errors.Is(err, errFindingScanMissing):
		uiInternal(w, err)
	case errors.As(err, &missing), errors.As(err, &precondition):
		writeUIError(w, http.StatusPreconditionFailed, uiCodePreconditionFailed, err.Error(), nil)
	case errors.Is(err, ErrFederationClaimPending):
		var f db.Finding
		s.DB.Select("id", "federation_claim_contacts").First(&f, findingID)
		writeUIErrorExtra(w, http.StatusConflict, uiCodeFederationClaimed, err.Error(),
			map[string]any{uiActKeyContacts: uiClaimContacts(f.FederationClaimContacts)})
	default:
		mapEnqueueErr(w, err)
	}
}

// ---------------------------------------------------------------- #20 exposure

type uiModelBody struct {
	Model string `json:"model"`
}

// uiFindingExposure is POST /ui/findings/{id}/actions/exposure: one exposure
// scan per top-N dependent. 202 with the batch counts.
func (s *Server) uiFindingExposure(w http.ResponseWriter, r *http.Request) {
	f, ok := s.uiActionFinding(w, r)
	if !ok {
		return
	}
	var body uiModelBody
	if !decodeUIActionBody(w, r, &body, uiActionBodyMax, true) {
		return
	}
	res, err := s.enqueueExposure(r.Context(), f, body.Model)
	switch {
	case errors.Is(err, errFindingScanMissing):
		uiInternal(w, err)
		return
	case errors.Is(err, errExposureSkillMissing):
		writeUIError(w, http.StatusPreconditionFailed, uiCodePreconditionFailed, err.Error(), nil)
		return
	case err != nil:
		writeUIError(w, http.StatusUnprocessableEntity, uiCodeValidationFailed, err.Error(), nil)
		return
	}
	res.Message = exposureRunToast(res.Queued, res.Skipped, res.Errored).Title
	if res.Skipped > 0 {
		s.publishFinding(f.ID, f.RepositoryID, uiChangeUpdated, "exposure")
	}
	enqueueBatchResult(w, res)
}

// ---------------------------------------------------------------- #21 validate-fix

type uiValidateFixBody struct {
	Ref        string `json:"ref"`
	Model      string `json:"model"`
	FindingIDs []uint `json:"finding_ids"`
}

// uiFindingValidateFix is POST /ui/findings/{id}/actions/validate-fix: the
// fix-validation pipeline for this finding (or finding_ids on its repository)
// against ref. 202 {scan_id (anchor), verify_scan_ids}.
func (s *Server) uiFindingValidateFix(w http.ResponseWriter, r *http.Request) {
	f, ok := s.uiActionFinding(w, r)
	if !ok {
		return
	}
	var body uiValidateFixBody
	if !decodeUIActionBody(w, r, &body, uiActionBodyMax, false) {
		return
	}
	ids := []uint{f.ID}
	if len(body.FindingIDs) > 0 {
		ids = ids[:0]
		for _, id := range body.FindingIDs {
			if id != 0 && !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	res, err := s.enqueueValidateFix(r.Context(), f.RepositoryID, strings.TrimSpace(body.Ref), ids, body.Model)
	var input validateFixInputError
	switch {
	case errors.As(err, &input):
		writeUIFields(w, uiFieldErrors{input.Field: input.Msg})
		return
	case err != nil:
		mapEnqueueErr(w, err)
		return
	}
	writeUIJSON(w, http.StatusAccepted, map[string]any{uiEventScanIDKey: res.AnchorID, "verify_scan_ids": res.VerifyScanIDs})
}

// ---------------------------------------------------------------- #26/#27 conversations

// uiFindingConversationRow is the ConversationRow projection.
// TODO(lead): WP-API-4 owns the chat projections; fold this into theirs.
func (s *Server) uiFindingConversationRow(c db.Conversation) map[string]any {
	return map[string]any{
		"id": c.ID, repositoryIDKey: c.RepositoryID, "finding_id": c.FindingID, uiActKeyTitle: c.Title,
		uiKeyModel: c.Model, "active": s.chatTurnActive(c.ID), uiKeyCreatedAt: c.CreatedAt, "updated_at": c.UpdatedAt,
	}
}

// uiFindingConversations is GET /ui/findings/{id}/conversations.
func (s *Server) uiFindingConversations(w http.ResponseWriter, r *http.Request) {
	f, ok := s.uiActionFinding(w, r)
	if !ok {
		return
	}
	convs, err := db.ConversationsFor(s.DB, f.RepositoryID, &f.ID)
	if err != nil {
		uiInternal(w, err)
		return
	}
	out := make([]map[string]any, len(convs))
	for i, c := range convs {
		out[i] = s.uiFindingConversationRow(c)
	}
	writeUIJSON(w, http.StatusOK, out)
}

type uiConversationBody struct {
	Message string `json:"message"`
}

// errConversationRepoUnknown is a legacy finding whose repository cannot be
// resolved.
var errConversationRepoUnknown = errors.New("could not resolve which repository this finding belongs to")

// uiFindingConversationCreate is POST /ui/findings/{id}/conversations: the
// finding page's chat starter. It persists the first message and starts the
// opening turn (model work), returning 201 ConversationDetail.
func (s *Server) uiFindingConversationCreate(w http.ResponseWriter, r *http.Request) {
	f, ok := s.uiActionFinding(w, r)
	if !ok {
		return
	}
	var body uiConversationBody
	if !decodeUIActionBody(w, r, &body, uiActionBodyMax, false) {
		return
	}
	if s.chatRunner == nil {
		writeUIError(w, http.StatusServiceUnavailable, uiCodeUnavailable, "chat is unavailable: no agent runner is configured", nil)
		return
	}
	message := strings.TrimSpace(body.Message)
	if message == "" {
		writeUIFields(w, uiFieldErrors{uiActKeyMessage: "type a message to start the conversation"})
		return
	}
	conv, err := s.startFindingConversation(f, message)
	if err != nil {
		uiInternal(w, err)
		return
	}
	s.publishFinding(f.ID, conv.RepositoryID, uiChangeUpdated, "conversations")
	loaded, err := db.LoadConversation(s.DB, conv.ID)
	if err != nil {
		uiDBError(w, err, "conversation")
		return
	}
	row := s.uiFindingConversationRow(*loaded)
	messages := make([]map[string]any, len(loaded.Messages))
	for i, m := range loaded.Messages {
		messages[i] = uiChatMessage(m)
	}
	row["messages"] = messages
	row["back"] = map[string]any{repositoryIDKey: loaded.RepositoryID, "finding_id": loaded.FindingID}
	writeUIJSON(w, http.StatusCreated, row)
}

// startFindingConversation mirrors startConversation (chat.go) without the
// redirect/flash: create the conversation, persist the first message and
// start the opening turn.
// TODO(lead): WP-API-4 extracts startConversation to return the
// conversation; switch to it after both merge.
func (s *Server) startFindingConversation(f db.Finding, message string) (*db.Conversation, error) {
	repoID := f.RepositoryID
	if repoID == 0 {
		// Legacy rows may not have the denormalized repository_id; fall back to
		// the producing scan, mirroring conversationCreateFinding.
		var scan db.Scan
		if err := s.DB.First(&scan, f.ScanID).Error; err != nil {
			return nil, errConversationRepoUnknown
		}
		repoID = scan.RepositoryID
	}
	fid := f.ID
	conv, err := db.CreateConversation(s.DB, repoID, &fid, s.DefaultModel(), message)
	if err != nil {
		return nil, err
	}
	if _, err := db.AddChatMessage(s.DB, conv.ID, db.ChatRoleUser, message); err != nil {
		// The conversation row is already committed; drop it rather than leave
		// a titled, message-less chat in the panel.
		s.DB.Delete(&db.Conversation{}, conv.ID)
		return nil, err
	}
	s.beginChatTurn(conv.ID)
	s.spawnTurn(conv.ID, message)
	return conv, nil
}
