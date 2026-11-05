package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// Finding writes (#11 PATCH, #17 notes/communications/references/reviews/
// labels, #18 dependent campaign). Every write uses db.SourceAnalyst, goes
// through the db helpers the HTML forms use, and publishes exactly one
// `finding` SSE event per successful transaction.

const (
	uiLabelNameMax = 64
	// uiIfMatchGrace absorbs the gap between the updated_at a write stamps
	// and the created_at of the history row it appends a moment later, so
	// a client's own previous save never reads as a concurrent change.
	uiIfMatchGrace = time.Second

	uiNotEditable  = "not editable by analysts"
	uiFieldChanged = "changed since you loaded it"

	uiFieldDisclosureDraft = "disclosure_draft"
	uiFieldCVSSVector      = "cvss_vector"
	uiFieldCVSSv4Vector    = "cvss_v4_vector"
	uiFieldExploited       = "exploited_in_wild"
	uiFieldExploitedEvid   = "exploited_in_wild_evidence"

	uiEventNotes          = "notes"
	uiEventCommunications = "communications"
	uiEventReferences     = "references"
	uiEventReviews        = "reviews"
	uiEventLabels         = "labels"
	uiEventCampaign       = "campaign"
)

var uiGHSAIDRE = regexp.MustCompile("^" + db.GHSAIDPattern + "$")

// uiFindingResolutions is the resolution vocabulary the PATCH accepts.
var uiFindingResolutions = []string{"", string(db.ResolutionFix), string(db.ResolutionMigrate),
	string(db.ResolutionWorkaround), string(db.ResolutionAdopt), string(db.ResolutionWontfix)}

// uiFindingFieldGetters are the analyst-editable fields (analystFields plus
// exploited_in_wild/_evidence) and their current-value getters. Every other
// db.findingFieldAccessors field is automation-owned and refused with 422.
var uiFindingFieldGetters = map[string]func(*db.Finding) string{
	uiKeyTitle:             func(f *db.Finding) string { return f.Title },
	uiFacetSeverity:        func(f *db.Finding) string { return f.Severity },
	uiKeyCWE:               func(f *db.Finding) string { return f.CWE },
	"location":             func(f *db.Finding) string { return f.Location },
	"affected":             func(f *db.Finding) string { return f.Affected },
	"cve_id":               func(f *db.Finding) string { return f.CVEID },
	"ghsa_id":              func(f *db.Finding) string { return f.GHSAID },
	uiFieldCVSSVector:      func(f *db.Finding) string { return f.CVSSVector },
	uiFieldCVSSv4Vector:    func(f *db.Finding) string { return f.CVSSv4Vector },
	"fix_version":          func(f *db.Finding) string { return f.FixVersion },
	"fix_commit":           func(f *db.Finding) string { return f.FixCommit },
	"resolution":           func(f *db.Finding) string { return string(f.Resolution) },
	uiFieldDisclosureDraft: func(f *db.Finding) string { return f.DisclosureDraft },
	"disclosure_title":     func(f *db.Finding) string { return f.DisclosureTitle },
	"suggested_recipients": func(f *db.Finding) string { return f.SuggestedRecipients },
	"assignee":             func(f *db.Finding) string { return f.Assignee },
	uiFieldExploited:       func(f *db.Finding) string { return f.ExploitedInWild },
	uiFieldExploitedEvid:   func(f *db.Finding) string { return f.ExploitedInWildEvidence },
}

// ---------------------------------------------------------------- body decoding

// decodeUIFindingBody decodes a JSON body (capped at apiMaxBody), writing a
// 400 bad_param when it is not valid JSON.
//
//nolint:ireturn // T is a concrete struct at every call site, not an interface
func decodeUIFindingBody[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var body T
	r.Body = http.MaxBytesReader(w, r.Body, apiMaxBody)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		uiBadParam(w, "body must be a JSON object: "+err.Error())
		return body, false
	}
	return body, true
}

// uiFindingErrStatus maps a finding write error to its status and envelope
// code: validation → 422, non-viable → 412, federation claim → 409,
// context timeout → 503, missing → 404, else 500.
func uiFindingErrStatus(err error) (int, string) {
	switch {
	case apiFieldsError(err) != nil, errors.Is(err, db.ErrInvalidFindingReview):
		return http.StatusUnprocessableEntity, uiCodeValidationFailed
	case errors.Is(err, db.ErrFindingNonViable):
		return http.StatusPreconditionFailed, uiCodePreconditionFailed
	case errors.Is(err, ErrFederationClaimPending):
		return http.StatusConflict, uiCodeFederationClaimed
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return http.StatusServiceUnavailable, uiCodeUnavailable
	case errors.Is(err, gorm.ErrRecordNotFound):
		return http.StatusNotFound, uiCodeNotFound
	default:
		return http.StatusInternalServerError, uiCodeInternal
	}
}

// uiFindingWriteError writes a finding write error in the UI envelope.
func uiFindingWriteError(w http.ResponseWriter, err error) {
	status, code := uiFindingErrStatus(err)
	writeUIError(w, status, code, err.Error(), apiFieldsError(err))
}

// ---------------------------------------------------------------- PATCH /ui/findings/{id} (#11)

type uiFindingPatchBody struct {
	Fields   map[string]string `json:"fields"`
	By       string            `json:"by"`
	Previous map[string]string `json:"previous"`
}

// normalizeUIFindingFields validates a PATCH/batch field map against the
// analyst vocabulary and returns the normalised values (trimmed; CRLF→LF in
// the disclosure draft, as findingDisclosureDraftSave does). Status-agnostic
// and shared with the batch endpoint.
func normalizeUIFindingFields(in map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(in))
	errs := uiFieldErrors{}
	for field, raw := range in {
		if _, ok := uiFindingFieldGetters[field]; !ok {
			if field == statusKey {
				errs[field] = uiNotEditable + "; use POST /api/v1/ui/findings/{id}/status"
			} else {
				errs[field] = uiNotEditable
			}
			continue
		}
		v := strings.TrimSpace(raw)
		if field == uiFieldDisclosureDraft {
			v = strings.TrimSpace(strings.ReplaceAll(raw, "\r\n", "\n"))
		}
		if msg := uiFindingFieldInvalid(field, v); msg != "" {
			errs[field] = msg
			continue
		}
		out[field] = v
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return out, nil
}

// uiFindingFieldInvalid is the enum/format pre-check the HTML form relied on
// datalists and selects for; "" means valid.
func uiFindingFieldInvalid(field, v string) string {
	switch field {
	case uiFacetSeverity:
		if v != "" && !slices.Contains(db.SeverityLevels, v) {
			return "must be one of " + strings.Join(db.SeverityLevels, ", ") + " or empty"
		}
	case "resolution":
		if !slices.Contains(uiFindingResolutions, v) {
			return "must be one of fix, migrate, workaround, adopt, wontfix or empty"
		}
	case uiFieldExploited:
		if v != "" && v != "yes" && v != "no" {
			return "must be yes, no, or empty"
		}
	case "ghsa_id":
		if v != "" && !uiGHSAIDRE.MatchString(v) {
			return "not a valid GHSA id (expected GHSA-xxxx-xxxx-xxxx)"
		}
	}
	return ""
}

// errUIFindingConflict carries the fields whose stored value moved under the
// client; FindingWriteTransaction does not retry it.
type errUIFindingConflict []string

func (e errUIFindingConflict) Error() string {
	return "finding changed since you loaded it: " + strings.Join(e, ", ")
}

// uiFieldChangedSince reports whether field's value differs from what it was
// at version `since`: the first history row written after since (+grace)
// holds that value as old_value. A field that moved and came back is not a
// conflict; a write that only bumped updated_at (worker seen counts,
// verdicts) is not either.
func uiFieldChangedSince(tx *gorm.DB, findingID uint, field, current string, since time.Time) (bool, error) {
	var rows []db.FindingHistory
	if err := tx.Where("finding_id = ? AND field = ?", findingID, field).Order("id").Find(&rows).Error; err != nil {
		return false, err
	}
	cutoff := since.Add(uiIfMatchGrace)
	for _, h := range rows {
		if h.CreatedAt.After(cutoff) {
			return h.OldValue != current, nil
		}
	}
	return false, nil
}

// applyUIFindingFields writes fields inside one FindingWriteTransaction with
// the per-field compare-and-swap of 02 §2.2: a field equal to its stored
// value is a no-op; otherwise it conflicts when the client's `previous`
// value differs from the stored one, or when If-Match is stale and the field
// itself changed since. Returns the fields actually written. Status-agnostic
// and shared with the batch endpoint (which passes no guards).
func (s *Server) applyUIFindingFields(ctx context.Context, id uint, fields, previous map[string]string,
	ifMatchAt time.Time, ifMatchSet bool, by string,
) ([]string, error) {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	var written []string
	err := db.FindingWriteTransaction(s.DB.WithContext(ctx), id, func(tx *gorm.DB) error {
		var f db.Finding
		if err := tx.First(&f, id).Error; err != nil {
			return err
		}
		guard := uiFieldGuard{previous: previous, since: ifMatchAt, stale: ifMatchSet && !sameVersion(ifMatchAt, f.UpdatedAt)}
		var err error
		if written, err = guard.check(tx, f, names, fields); err != nil {
			return err
		}
		for _, name := range written {
			if err := db.WriteFindingField(tx, id, name, fields[name], db.SourceAnalyst, by); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return written, nil
}

// uiFieldGuard is the per-field compare-and-swap input of one PATCH.
type uiFieldGuard struct {
	previous map[string]string
	since    time.Time
	stale    bool
}

// check returns the fields that need writing (value differs from stored),
// or errUIFindingConflict naming those whose stored value moved under the
// client.
func (g uiFieldGuard) check(tx *gorm.DB, f db.Finding, names []string, fields map[string]string) ([]string, error) {
	var written []string
	var conflicts errUIFindingConflict
	for _, name := range names {
		current := uiFindingFieldGetters[name](&f)
		if current == fields[name] {
			continue
		}
		conflict := false
		if prev, ok := g.previous[name]; ok && prev != current {
			conflict = true
		} else if g.stale {
			changed, err := uiFieldChangedSince(tx, f.ID, name, current, g.since)
			if err != nil {
				return nil, err
			}
			conflict = changed
		}
		if conflict {
			conflicts = append(conflicts, name)
		} else {
			written = append(written, name)
		}
	}
	if len(conflicts) > 0 {
		return nil, conflicts
	}
	return written, nil
}

// uiWrittenFieldValues is the PATCH response's `fields`: the stored value of
// every requested field, plus the derived CVSS scores when a vector was set.
func uiWrittenFieldValues(f db.Finding, requested map[string]string) map[string]any {
	out := make(map[string]any, len(requested))
	for name := range requested {
		out[name] = uiFindingFieldGetters[name](&f)
	}
	if _, ok := requested[uiFieldCVSSVector]; ok {
		out["cvss_score"] = f.CVSSScore
	}
	if _, ok := requested[uiFieldCVSSv4Vector]; ok {
		out["cvss_v4_score"] = f.CVSSv4Score
	}
	return out
}

func (s *Server) uiFindingPatch(w http.ResponseWriter, r *http.Request) {
	id, ok := s.uiFindingExists(w, r)
	if !ok {
		return
	}
	body, ok := decodeUIFindingBody[uiFindingPatchBody](w, r)
	if !ok {
		return
	}
	if body.Fields == nil {
		uiBadParam(w, "body must carry a fields object")
		return
	}
	fields, err := normalizeUIFindingFields(body.Fields)
	if err != nil {
		writeUIFields(w, err)
		return
	}
	ifMatchAt, ifMatchSet := ifMatch(r)
	written, err := s.applyUIFindingFields(r.Context(), id, fields, body.Previous, ifMatchAt, ifMatchSet, strings.TrimSpace(body.By))
	var conflict errUIFindingConflict
	if errors.As(err, &conflict) {
		s.writeUIFindingConflict(w, id, conflict)
		return
	}
	if err != nil {
		uiFindingWriteError(w, err)
		return
	}
	f, _, err := s.loadUIFindingRow(id)
	if err != nil {
		uiDBError(w, err, uiFindingWhat)
		return
	}
	if len(written) > 0 {
		s.publishFinding(id, f.RepositoryID, uiChangeUpdated, written...)
	}
	s.writeUIFindingResult(w, r, id, map[string]any{"fields": uiWrittenFieldValues(f, fields)})
}

// writeUIFindingConflict writes 409 {code:conflict, current: FindingRow,
// fields:{name: "changed since you loaded it"}} with the current ETag.
func (s *Server) writeUIFindingConflict(w http.ResponseWriter, id uint, fields []string) {
	f, row, err := s.loadUIFindingRow(id)
	if err != nil {
		uiDBError(w, err, uiFindingWhat)
		return
	}
	perField := make(map[string]string, len(fields))
	for _, name := range fields {
		perField[name] = uiFieldChanged
	}
	setETag(w, f.UpdatedAt)
	writeUIErrorExtra(w, http.StatusConflict, uiCodeConflict, errUIFindingConflict(fields).Error(),
		map[string]any{"current": row, "fields": perField})
}

// ---------------------------------------------------------------- notes, communications, references, reviews (#17)

// uiFindingRepoID loads the repository id an event for finding id is scoped to.
func (s *Server) uiFindingRepoID(id uint) uint {
	repoID, _ := s.findingRepoID(id)
	return repoID
}

func (s *Server) uiFindingNoteCreate(w http.ResponseWriter, r *http.Request) {
	id, ok := s.uiFindingExists(w, r)
	if !ok {
		return
	}
	body, ok := decodeUIFindingBody[struct {
		Body string `json:"body"`
		By   string `json:"by"`
	}](w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(body.Body) == "" {
		writeUIFields(w, uiFieldErrors{"body": "note body is empty"})
		return
	}
	n, err := db.AddFindingNote(s.DB.WithContext(r.Context()), id, body.Body, strings.TrimSpace(body.By))
	if err != nil {
		uiFindingWriteError(w, err)
		return
	}
	s.publishFinding(id, s.uiFindingRepoID(id), uiChangeUpdated, uiEventNotes)
	writeUIJSON(w, http.StatusCreated, uiFindingNote(*n))
}

// Vocabularies of the communication form's selects.
var (
	uiCommunicationChannels   = []string{"email", "ghsa", "issue", "pr", "direct", "registry"}
	uiCommunicationDirections = []string{"", "outbound", "inbound"}
	uiCommunicationOffers     = []string{"", "pr", "funding", "adoption", "none"}
)

type uiCommunicationBody struct {
	Channel     string `json:"channel"`
	Direction   string `json:"direction"`
	Actor       string `json:"actor"`
	Body        string `json:"body"`
	OfferedHelp string `json:"offered_help"`
	At          string `json:"at"`
}

// parseUICommunicationAt accepts YYYY-MM-DD (the HTML date input) or
// RFC3339; empty is the zero time, which AddFindingCommunication turns into now.
func parseUICommunicationAt(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.DateOnly, v); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, v)
}

func (b uiCommunicationBody) validate() (time.Time, error) {
	errs := uiFieldErrors{}
	if !slices.Contains(uiCommunicationChannels, b.Channel) {
		errs["channel"] = "must be one of " + strings.Join(uiCommunicationChannels, ", ")
	}
	if !slices.Contains(uiCommunicationDirections, b.Direction) {
		errs["direction"] = "must be outbound, inbound or empty"
	}
	if !slices.Contains(uiCommunicationOffers, b.OfferedHelp) {
		errs["offered_help"] = "must be pr, funding, adoption, none or empty"
	}
	at, err := parseUICommunicationAt(b.At)
	if err != nil {
		errs["at"] = "must be YYYY-MM-DD or RFC3339"
	}
	if len(errs) > 0 {
		return at, errs
	}
	return at, nil
}

func (s *Server) uiFindingCommunicationCreate(w http.ResponseWriter, r *http.Request) {
	id, ok := s.uiFindingExists(w, r)
	if !ok {
		return
	}
	body, ok := decodeUIFindingBody[uiCommunicationBody](w, r)
	if !ok {
		return
	}
	at, err := body.validate()
	if err != nil {
		writeUIFields(w, err)
		return
	}
	c, err := db.AddFindingCommunication(s.DB.WithContext(r.Context()), id, body.Channel, body.Direction,
		body.Actor, body.Body, body.OfferedHelp, at, db.SourceAnalyst)
	if err != nil {
		uiFindingWriteError(w, err)
		return
	}
	s.publishFinding(id, s.uiFindingRepoID(id), uiChangeUpdated, uiEventCommunications)
	writeUIJSON(w, http.StatusCreated, uiFindingCommunication(*c))
}

// uiReferenceURLInvalid requires an absolute http(s) URL: the SPA renders
// references as links, so javascript: and friends never get stored here.
func uiReferenceURLInvalid(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "reference url is empty"
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "must be an absolute http(s) URL"
	}
	return ""
}

func (s *Server) uiFindingReferenceCreate(w http.ResponseWriter, r *http.Request) {
	id, ok := s.uiFindingExists(w, r)
	if !ok {
		return
	}
	body, ok := decodeUIFindingBody[struct {
		URL     string `json:"url"`
		Tags    string `json:"tags"`
		Summary string `json:"summary"`
	}](w, r)
	if !ok {
		return
	}
	if msg := uiReferenceURLInvalid(body.URL); msg != "" {
		writeUIFields(w, uiFieldErrors{uiKeyURL: msg})
		return
	}
	ref, err := db.AddFindingReference(s.DB.WithContext(r.Context()), id, body.URL, body.Tags, body.Summary)
	if err != nil {
		uiFindingWriteError(w, err)
		return
	}
	s.publishFinding(id, s.uiFindingRepoID(id), uiChangeUpdated, uiEventReferences)
	writeUIJSON(w, http.StatusCreated, uiFindingReference(*ref))
}

func (s *Server) uiFindingReviewCreate(w http.ResponseWriter, r *http.Request) {
	id, ok := s.uiFindingExists(w, r)
	if !ok {
		return
	}
	body, ok := decodeUIFindingBody[struct {
		Verdict          string `json:"verdict"`
		Reason           string `json:"reason"`
		Reviewer         string `json:"reviewer"`
		AutomatedOutcome string `json:"automated_outcome"`
	}](w, r)
	if !ok {
		return
	}
	// As findingReviewCreate: a blank automated outcome is the latest
	// revalidate verdict.
	automated := body.AutomatedOutcome
	if automated == "" {
		automated = db.LatestRevalidateVerdict(s.DB, id)
	}
	rv, err := db.AddFindingReview(s.DB.WithContext(r.Context()), id, body.Verdict, body.Reason, automated, body.Reviewer)
	if err != nil {
		uiFindingWriteError(w, err)
		return
	}
	s.publishFinding(id, s.uiFindingRepoID(id), uiChangeUpdated, uiEventReviews)
	writeUIJSON(w, http.StatusCreated, uiFindingReview(*rv))
}

// ---------------------------------------------------------------- labels (#17)

// normalizeUILabelNames trims, drops blanks and validates label names.
func normalizeUILabelNames(raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	for _, n := range raw {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if utf8.RuneCountInString(n) > uiLabelNameMax {
			return nil, uiFieldErrors{"labels": fmt.Sprintf("label %q is longer than %d characters", n, uiLabelNameMax)}
		}
		out = append(out, n)
	}
	return out, nil
}

// uiSetFindingLabels replaces a finding's labels through db.SetFindingLabels
// (FirstOrCreate by name, so unknown names are created with no colour) and
// reports whether any catalogue label was created. Status-agnostic, shared
// with the batch endpoint.
func (s *Server) uiSetFindingLabels(ctx context.Context, id uint, names []string, by string) (bool, error) {
	var before int64
	if len(names) > 0 {
		s.DB.Model(&db.FindingLabel{}).Where("name IN ?", names).Count(&before)
	}
	if err := db.SetFindingLabels(s.DB.WithContext(ctx), id, names, db.SourceAnalyst, by); err != nil {
		return false, err
	}
	if len(names) == 0 {
		return false, nil
	}
	var after int64
	s.DB.Model(&db.FindingLabel{}).Where("name IN ?", names).Count(&after)
	return after > before, nil
}

func (s *Server) uiFindingLabelsPut(w http.ResponseWriter, r *http.Request) {
	id, ok := s.uiFindingExists(w, r)
	if !ok {
		return
	}
	body, ok := decodeUIFindingBody[struct {
		Labels []string `json:"labels"`
		By     string   `json:"by"`
	}](w, r)
	if !ok {
		return
	}
	// As apiSetFindingLabels: a missing array must not wipe the labels.
	if body.Labels == nil {
		uiBadParam(w, "body must carry a labels array")
		return
	}
	names, err := normalizeUILabelNames(body.Labels)
	if err != nil {
		writeUIFields(w, err)
		return
	}
	created, err := s.uiSetFindingLabels(r.Context(), id, names, strings.TrimSpace(body.By))
	if err != nil {
		uiFindingWriteError(w, err)
		return
	}
	f, _, err := s.loadUIFindingRow(id)
	if err != nil {
		uiDBError(w, err, uiFindingWhat)
		return
	}
	s.publishFinding(id, f.RepositoryID, uiChangeUpdated, uiEventLabels)
	if created {
		s.publishMeta(uiEventLabels)
	}
	writeUIJSON(w, http.StatusOK, uiLabels(sortedLabels(f.Labels)))
}

// ---------------------------------------------------------------- campaign (#18)

func uiCampaignRow(row db.FindingDependent) map[string]any {
	return map[string]any{
		"id": row.ID, "finding_id": row.FindingID, "dependent_id": row.DependentID,
		statusKey: string(row.CampaignStatus), "note": row.CampaignNote, uiKeyUpdatedAt: row.CampaignUpdatedAt,
	}
}

func (s *Server) uiFindingCampaignPatch(w http.ResponseWriter, r *http.Request) {
	id, ok := s.uiFindingExists(w, r)
	if !ok {
		return
	}
	dependentID, ok := uiPathID(w, r, "dependent_id")
	if !ok {
		return
	}
	body, ok := decodeUIFindingBody[struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}](w, r)
	if !ok {
		return
	}
	row, err := db.SetFindingDependentCampaign(s.DB.WithContext(r.Context()), id, dependentID,
		db.DependentCampaignStatus(body.Status), body.Note)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		uiNotFound(w, "finding dependent")
		return
	}
	if err != nil {
		writeUIFields(w, uiFieldErrors{statusKey: err.Error()})
		return
	}
	s.publishFinding(id, s.uiFindingRepoID(id), uiChangeUpdated, uiEventCampaign)
	writeUIJSON(w, http.StatusOK, uiCampaignRow(row))
}
