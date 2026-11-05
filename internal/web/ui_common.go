package web

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

// Shared plumbing for the /api/v1/ui JSON surface the Svelte UI uses
// (docs: 02-api-plan.md section 2). Every domain package builds on these so
// the envelope, error, paging and versioning rules are identical everywhere.

const (
	uiDefaultPageSize = 20
	uiMaxPageSize     = 200
	// uiPageSizeAll is the `page_size=all` spelling some lists accept; it
	// means the maximum page.
	uiPageSizeAll = "all"

	requestIDHeader = "X-Request-Id"
	requestIDBytes  = 8

	cacheControlHeader = "Cache-Control"
	noStore            = "no-store"

	// Error codes of the UI error envelope.
	uiCodeUnauthorized       = "unauthorized"
	uiCodeForbidden          = "forbidden"
	uiCodeNotFound           = "not_found"
	uiCodeBadParam           = "bad_param"
	uiCodeValidationFailed   = "validation_failed"
	uiCodeConflict           = "conflict"
	uiCodeInFlight           = "in_flight"
	uiCodePreconditionFailed = "precondition_failed"
	uiCodeFederationClaimed  = "federation_claimed"
	uiCodeNetwork            = "network"
	uiCodeUnavailable        = "unavailable"
	uiCodeInternal           = "internal"

	// JSON keys and column names repeated across the UI projections.
	uiKeyName      = "name"
	uiKeyModel     = "model"
	uiKeyCreatedAt = "created_at"
	uiKeyFindings  = "findings"
)

// ---------------------------------------------------------------- request id

// withRequestID tags a request with an id: echoed in X-Request-Id, logged by
// logRequests and copied into every UI error envelope so a toast can be
// matched to a log line. An inbound X-Request-Id is not trusted.
func withRequestID(w http.ResponseWriter) string {
	b := make([]byte, requestIDBytes)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	w.Header().Set(requestIDHeader, id)
	return id
}

// responseRequestID reads the id withRequestID stored on the response, minting
// one when a handler runs without logRequests (unit tests).
func responseRequestID(w http.ResponseWriter) string {
	if id := w.Header().Get(requestIDHeader); id != "" {
		return id
	}
	return withRequestID(w)
}

// ---------------------------------------------------------------- JSON + errors

// writeUIJSON writes a UI response. TanStack Query is the only cache, so the
// default is no-store; handlers that want caching set Cache-Control first.
func writeUIJSON(w http.ResponseWriter, code int, v any) {
	if w.Header().Get(cacheControlHeader) == "" {
		w.Header().Set(cacheControlHeader, noStore)
	}
	writeJSON(w, code, v)
}

// writeUIError writes the UI error envelope. fields is optional (422).
func writeUIError(w http.ResponseWriter, status int, code, msg string, fields map[string]string) {
	var extra map[string]any
	if len(fields) > 0 {
		extra = map[string]any{"fields": fields}
	}
	writeUIErrorExtra(w, status, code, msg, extra)
}

// writeUIErrorExtra writes the envelope with additional keys (`current` on a
// conflict, `scan_id` on in_flight, `contacts` on federation_claimed).
func writeUIErrorExtra(w http.ResponseWriter, status int, code, msg string, extra map[string]any) {
	if code == "" {
		code = uiCodeForStatus(status)
	}
	body := map[string]any{errorKey: msg, "code": code, "request_id": responseRequestID(w)}
	for k, v := range extra {
		body[k] = v
	}
	writeUIJSON(w, status, body)
}

// uiCodeForStatus is the default envelope code for a status.
func uiCodeForStatus(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return uiCodeUnauthorized
	case http.StatusForbidden:
		return uiCodeForbidden
	case http.StatusNotFound:
		return uiCodeNotFound
	case http.StatusBadRequest:
		return uiCodeBadParam
	case http.StatusUnprocessableEntity:
		return uiCodeValidationFailed
	case http.StatusConflict:
		return uiCodeConflict
	case http.StatusPreconditionFailed:
		return uiCodePreconditionFailed
	case http.StatusBadGateway:
		return uiCodeNetwork
	case http.StatusServiceUnavailable:
		return uiCodeUnavailable
	default:
		return uiCodeInternal
	}
}

func uiBadParam(w http.ResponseWriter, msg string) {
	writeUIError(w, http.StatusBadRequest, uiCodeBadParam, msg, nil)
}

func uiNotFound(w http.ResponseWriter, what string) {
	writeUIError(w, http.StatusNotFound, uiCodeNotFound, what+" not found", nil)
}

func uiInternal(w http.ResponseWriter, err error) {
	writeUIError(w, http.StatusInternalServerError, uiCodeInternal, err.Error(), nil)
}

// uiDBError maps a lookup error: record-not-found → 404, anything else → 500.
func uiDBError(w http.ResponseWriter, err error, what string) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		uiNotFound(w, what)
		return
	}
	uiInternal(w, err)
}

// uiFieldErrors is a validation error naming the offending fields; handlers
// return it from their parse/validate step and write it with writeUIFields.
type uiFieldErrors map[string]string

func (e uiFieldErrors) Error() string {
	parts := make([]string, 0, len(e))
	for k, v := range e {
		parts = append(parts, k+": "+v)
	}
	return strings.Join(parts, "; ")
}

// apiFieldsError extracts per-field messages from err when it is (or wraps) a
// uiFieldErrors; nil otherwise.
func apiFieldsError(err error) map[string]string {
	var fe uiFieldErrors
	if errors.As(err, &fe) {
		return fe
	}
	return nil
}

// writeUIFields writes a 422 for a validation error.
func writeUIFields(w http.ResponseWriter, err error) {
	writeUIError(w, http.StatusUnprocessableEntity, uiCodeValidationFailed, err.Error(), apiFieldsError(err))
}

// ---------------------------------------------------------------- paging

// listPage is a parsed page/page_size pair.
type listPage struct {
	Page     int
	PageSize int
}

func (p listPage) offset() int { return (p.Page - 1) * p.PageSize }

// parseListPage reads `page` (1-based, default 1) and `page_size` (default 20,
// max 200, `all` = 200). Out-of-range or non-numeric values are a bad_param.
func parseListPage(r *http.Request) (listPage, error) {
	return parseListPageDefault(r, uiDefaultPageSize)
}

// parseListPageDefault is parseListPage with a per-list default page size.
func parseListPageDefault(r *http.Request, defaultSize int) (listPage, error) {
	p := listPage{Page: 1, PageSize: defaultSize}
	q := r.URL.Query()
	if v := q.Get("page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return p, fmt.Errorf("page must be a positive integer, got %q", v)
		}
		p.Page = n
	}
	switch v := q.Get("page_size"); v {
	case "":
	case uiPageSizeAll:
		p.PageSize = uiMaxPageSize
	default:
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > uiMaxPageSize {
			return p, fmt.Errorf("page_size must be 1..%d or %q, got %q", uiMaxPageSize, uiPageSizeAll, v)
		}
		p.PageSize = n
	}
	return p, nil
}

// orderBy maps a sort token (`key` or `key.asc|.desc`) to an ORDER BY
// expression and the effective token. Each domain extracts its list's
// switch into one of these so the HTML and JSON lists share it.
type orderBy func(sortToken string) (expr, effective string)

// writeList writes the list envelope {items,total,page,page_size}.
func writeList(w http.ResponseWriter, items any, total int64, p listPage) {
	writeListWith(w, items, total, p, nil)
}

// writeListWith writes the list envelope plus list-specific keys (stats,
// counts, facets, ...). extra never overrides the envelope keys.
func writeListWith(w http.ResponseWriter, items any, total int64, p listPage, extra map[string]any) {
	const envelopeKeys = 4
	body := make(map[string]any, len(extra)+envelopeKeys)
	for k, v := range extra {
		body[k] = v
	}
	body["items"] = items
	body["total"] = total
	body["page"] = p.Page
	body["page_size"] = p.PageSize
	writeUIJSON(w, http.StatusOK, body)
}

// uiQueryID parses an optional positive integer query param; 0 when absent.
func uiQueryID(r *http.Request, name string) (uint, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("%s must be a positive integer, got %q", name, v)
	}
	return uint(n), nil
}

// uiPathID parses the {id} path value, writing a 400 when it is malformed.
func uiPathID(w http.ResponseWriter, r *http.Request, name string) (uint, bool) {
	n, err := strconv.ParseUint(r.PathValue(name), 10, 64)
	if err != nil || n == 0 {
		uiBadParam(w, "invalid "+name)
		return 0, false
	}
	return uint(n), true
}

// ---------------------------------------------------------------- ETag / If-Match

// etagFor renders updated_at as the quoted ETag the UI echoes in If-Match.
func etagFor(t time.Time) string {
	return `"` + t.Format(time.RFC3339Nano) + `"`
}

func setETag(w http.ResponseWriter, updatedAt time.Time) {
	w.Header().Set("ETag", etagFor(updatedAt))
}

// ifMatch reports the version the client expects. ok is false when the
// header is absent or `*` (last-write-wins). A malformed value yields the zero
// time with ok=true, which never matches, so the write is refused rather than
// silently applied.
func ifMatch(r *http.Request) (time.Time, bool) {
	v := strings.TrimSpace(r.Header.Get("If-Match"))
	if v == "" || v == "*" {
		return time.Time{}, false
	}
	v = strings.TrimPrefix(v, "W/")
	t, err := time.Parse(time.RFC3339Nano, strings.Trim(v, `"`))
	if err != nil {
		return time.Time{}, true
	}
	return t, true
}

// sameVersion compares two updated_at values at Postgres precision.
func sameVersion(a, b time.Time) bool {
	return a.Truncate(time.Microsecond).Equal(b.Truncate(time.Microsecond))
}

// checkIfMatch enforces If-Match against the stored updated_at. On mismatch it
// writes 409 {code:conflict, current} and returns false; current is the row
// projection of the stored entity.
func checkIfMatch(w http.ResponseWriter, r *http.Request, updatedAt time.Time, current any) bool {
	want, ok := ifMatch(r)
	if !ok || sameVersion(want, updatedAt) {
		return true
	}
	writeUIErrorExtra(w, http.StatusConflict, uiCodeConflict, "changed since you loaded it", map[string]any{"current": current})
	return false
}

// ---------------------------------------------------------------- enqueue

// enqueueResult writes 202 {scan_id}.
func enqueueResult(w http.ResponseWriter, scanID uint) {
	writeUIJSON(w, http.StatusAccepted, map[string]any{uiEventScanIDKey: scanID})
}

// enqueueBatch is the multi-scan enqueue response.
type enqueueBatch struct {
	ScanIDs []uint `json:"scan_ids"`
	Queued  int    `json:"queued"`
	Skipped int    `json:"skipped"`
	Errored int    `json:"errored"`
	Message string `json:"message,omitempty"`
}

// enqueueBatchResult writes 202 with the batch counts.
func enqueueBatchResult(w http.ResponseWriter, res enqueueBatch) {
	if res.ScanIDs == nil {
		res.ScanIDs = []uint{}
	}
	writeUIJSON(w, http.StatusAccepted, res)
}

// mapEnqueueErr writes the status the HTML handlers use for an enqueue error:
// 412 for a missing/non-viable precondition, 409 for an opt-out, a federation
// claim or a delete blocked by in-flight scans, 422 for bad input, 404 for a
// missing row, 500 otherwise.
func mapEnqueueErr(w http.ResponseWriter, err error) {
	status, code := enqueueErrStatus(err)
	writeUIError(w, status, code, err.Error(), nil)
}

func enqueueErrStatus(err error) (int, string) {
	switch {
	case errors.Is(err, errDeepDiveMissing), errors.Is(err, db.ErrFindingNonViable):
		return http.StatusPreconditionFailed, uiCodePreconditionFailed
	case errors.Is(err, ErrFederationClaimPending):
		return http.StatusConflict, uiCodeFederationClaimed
	case errors.Is(err, errRepositoryDeleteInFlight), errors.Is(err, errFindingDeleteInFlight):
		return http.StatusConflict, uiCodeInFlight
	case errors.Is(err, ErrRepoFederationOptOut):
		return http.StatusConflict, uiCodeConflict
	case errors.Is(err, ErrInvalidRef), errors.Is(err, ErrUnknownEgressPolicy), errors.Is(err, ErrInvalidMaxCost),
		errors.Is(err, ErrInvalidRescanMode), errors.Is(err, ErrSkillProfileMismatch):
		return http.StatusUnprocessableEntity, uiCodeValidationFailed
	case errors.Is(err, gorm.ErrRecordNotFound), errors.Is(err, ErrSkillRequiresRemote):
		return http.StatusNotFound, uiCodeNotFound
	default:
		return http.StatusInternalServerError, uiCodeInternal
	}
}

// ---------------------------------------------------------------- shared shapes

// uiTarget is a structured navigation target: the SPA owns its route table,
// so no payload carries an href.
type uiTarget struct {
	Kind    string `json:"kind"`
	ID      uint   `json:"id"`
	Section string `json:"section,omitempty"`
}

// uiToast mirrors Flash with the href replaced by a target.
type uiToast struct {
	Category    string    `json:"category"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Label       string    `json:"label,omitempty"`
	Target      *uiTarget `json:"target"`
}

// uiScanOmit are the blob columns a ScanRow never loads.
var uiScanOmit = []string{"log", "report", "prompt", "refusal_audit", "import_payload", "api_token", "recipe"}

// scanBlobSizes are the byte lengths of a scan's blobs.
type scanBlobSizes struct {
	ID          uint
	LogBytes    int64
	ReportBytes int64
	PromptBytes int64
}

// scanBlobSizeSelect is the dialect's byte-length projection of the blobs.
func scanBlobSizeSelect(gdb *gorm.DB) string {
	if gdb.Name() == string(db.DialectPostgres) {
		return "id, OCTET_LENGTH(log) AS log_bytes, OCTET_LENGTH(report) AS report_bytes, OCTET_LENGTH(prompt) AS prompt_bytes"
	}
	return "id, LENGTH(CAST(log AS BLOB)) AS log_bytes, LENGTH(CAST(report AS BLOB)) AS report_bytes, " +
		"LENGTH(CAST(prompt AS BLOB)) AS prompt_bytes"
}

// loadScanBlobSizes returns blob sizes keyed by scan id.
func loadScanBlobSizes(gdb *gorm.DB, ids []uint) map[uint]scanBlobSizes {
	out := make(map[uint]scanBlobSizes, len(ids))
	if len(ids) == 0 {
		return out
	}
	var rows []scanBlobSizes
	gdb.Model(&db.Scan{}).Select(scanBlobSizeSelect(gdb)).Where("id IN ?", ids).Scan(&rows)
	for _, row := range rows {
		out[row.ID] = row
	}
	return out
}

// scanRowActions mirrors the scan-actions template partial.
func scanRowActions(sc db.Scan) map[string]bool {
	cancel := sc.Status == db.ScanQueued || sc.Status == db.ScanRunning
	resume := !cancel && sc.Status == db.ScanPaused
	retry := !cancel && !resume && sc.SkillID != nil &&
		(sc.Status == db.ScanFailed || sc.Status == db.ScanCancelled || sc.MaxTurnsHit || sc.CostCapped)
	return map[string]bool{"cancel": cancel, "resume": resume, "retry": retry}
}

// exportableReportMinBytes approximates Scan.HasExportableReport for list
// rows, which never load the report blob.
const exportableReportMinBytes = 20

// uiScanRow is the ScanRow projection: scanSummary plus the list columns. sc
// must have Repository loaded (id, name) for the repository key.
func uiScanRow(sc db.Scan, sizes scanBlobSizes) map[string]any {
	m := scanSummary(sc)
	focus := scanFocus(sc)
	m["skill_id"] = sc.SkillID
	m["finding_id"] = sc.FindingID
	m["repository"] = map[string]any{"id": sc.RepositoryID, uiKeyName: sc.Repository.Name}
	m["findings_count"] = sc.FindingsCount
	m["cost_usd"] = sc.CostUSD
	m["turns"] = sc.Turns
	m["duration_seconds"] = sc.Duration().Seconds()
	m[uiKeyCreatedAt] = sc.CreatedAt
	m["updated_at"] = sc.UpdatedAt
	completeness := sc.Completeness
	if completeness == "" {
		completeness = coverage.CompletenessUnknown
	}
	m["completeness"] = completeness
	m["focus"] = map[string]string{uiKeyName: focus.Name, "paths": focus.Paths, "surface": focus.Surface, "group": focus.Group}
	m["scan_group"] = sc.ScanGroup
	m["resumable"] = sc.Resumable()
	m["has_exportable_report"] = sc.FindingsCount > 0 || sizes.ReportBytes >= exportableReportMinBytes
	m["actions"] = scanRowActions(sc)
	m["log_bytes"] = sizes.LogBytes
	m["report_bytes"] = sizes.ReportBytes
	m["prompt_bytes"] = sizes.PromptBytes
	return m
}

// uiScanRows runs q (filters, order, paging already applied) without the blob
// columns and projects each row as a ScanRow.
func (s *Server) uiScanRows(q *gorm.DB) ([]map[string]any, error) {
	var scans []db.Scan
	err := q.Omit(uiScanOmit...).Preload("Repository", func(tx *gorm.DB) *gorm.DB {
		return tx.Select("id", uiKeyName)
	}).Find(&scans).Error
	if err != nil {
		return nil, err
	}
	ids := make([]uint, len(scans))
	for i, sc := range scans {
		ids[i] = sc.ID
	}
	sizes := loadScanBlobSizes(s.DB, ids)
	out := make([]map[string]any, len(scans))
	for i, sc := range scans {
		out[i] = uiScanRow(sc, sizes[sc.ID])
	}
	return out, nil
}

// loadUIScanRow loads one ScanRow.
func (s *Server) loadUIScanRow(id uint) (map[string]any, error) {
	rows, err := s.uiScanRows(s.DB.Model(&db.Scan{}).Where("scans.id = ?", id))
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return rows[0], nil
}

// uiLocationRef parses "path:12-34" into a LocationRef; nil when empty.
func uiLocationRef(location, commit string) map[string]any {
	if strings.TrimSpace(location) == "" {
		return nil
	}
	path, lines := splitLocation(location)
	ref := map[string]any{"path": path, "line_start": 0, "line_end": nil, "commit": commit}
	if lines == "" {
		return ref
	}
	a, b, ranged := strings.Cut(lines, "-")
	if n, err := strconv.Atoi(a); err == nil {
		ref["line_start"] = n
	}
	if ranged {
		if n, err := strconv.Atoi(b); err == nil {
			ref["line_end"] = n
		}
	}
	return ref
}

// uiLabel is the Label object form.
func uiLabel(l db.FindingLabel) map[string]any {
	return map[string]any{"id": l.ID, uiKeyName: l.Name, "color": l.Color}
}

// uiFindingRow is the FindingRow projection of one finding. f must carry the
// Trace column (title_summary) and Labels; repo and skillName come from the
// batch loader. WP-API-1 extends it (expected match) without renaming keys.
func uiFindingRow(f db.Finding, repo db.Repository, skillName string) map[string]any {
	m := findingSummary(f)
	m["title_summary"] = f.Summary()
	m["repository"] = map[string]any{"id": repo.ID, uiKeyName: repo.Name, "full_name": repo.FullName, "owner": repo.Owner}
	labels := make([]map[string]any, len(f.Labels))
	for i, l := range f.Labels {
		labels[i] = uiLabel(l)
	}
	m["labels"] = labels
	m[uiKeyModel] = f.Model
	m[uiKeyCreatedAt] = f.CreatedAt
	m["updated_at"] = f.UpdatedAt
	m["location_ref"] = uiLocationRef(f.Location, f.Commit)
	locs := make([]map[string]any, 0)
	for _, l := range f.LocationList() {
		if ref := uiLocationRef(l, f.Commit); ref != nil {
			locs = append(locs, ref)
		}
	}
	m["locations"] = locs
	m["extra_location_count"] = f.ExtraLocationCount()
	if f.LastSeenScanID != 0 {
		m["last_seen_scan_id"] = f.LastSeenScanID
	} else {
		m["last_seen_scan_id"] = nil
	}
	m["skill_name"] = skillName
	m["expected"] = nil
	return m
}

// uiFindingRows projects findings as FindingRows, batch-loading their
// repositories, labels and producing skill names.
func (s *Server) uiFindingRows(findings []db.Finding) []map[string]any {
	repoIDs := make([]uint, 0, len(findings))
	scanIDs := make([]uint, 0, len(findings))
	for _, f := range findings {
		repoIDs = append(repoIDs, f.RepositoryID)
		scanIDs = append(scanIDs, f.ScanID)
	}
	repos := map[uint]db.Repository{}
	if len(repoIDs) > 0 {
		var rows []db.Repository
		s.DB.Select("id", uiKeyName, "full_name", "owner").Where("id IN ?", repoIDs).Find(&rows)
		for _, r := range rows {
			repos[r.ID] = r
		}
	}
	skills := map[uint]string{}
	if len(scanIDs) > 0 {
		var rows []db.Scan
		s.DB.Select("id", "skill_name").Where("id IN ?", scanIDs).Find(&rows)
		for _, sc := range rows {
			skills[sc.ID] = sc.SkillName
		}
	}
	s.loadFindingLabels(findings)
	out := make([]map[string]any, len(findings))
	for i, f := range findings {
		out[i] = uiFindingRow(f, repos[f.RepositoryID], skills[f.ScanID])
	}
	s.applyUIExpectedMatches(findings, out)
	return out
}

// loadFindingLabels fills Labels on findings that did not preload them.
func (s *Server) loadFindingLabels(findings []db.Finding) {
	if len(findings) == 0 {
		return
	}
	ids := make([]uint, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
	}
	var joins []struct {
		FindingID      uint
		FindingLabelID uint
	}
	s.DB.Table("finding_labels_join").Select("finding_id, finding_label_id").Where("finding_id IN ?", ids).Scan(&joins)
	if len(joins) == 0 {
		return
	}
	labelIDs := make([]uint, len(joins))
	for i, j := range joins {
		labelIDs[i] = j.FindingLabelID
	}
	var labels []db.FindingLabel
	s.DB.Where("id IN ?", labelIDs).Order(uiKeyName).Find(&labels)
	byID := make(map[uint]db.FindingLabel, len(labels))
	for _, l := range labels {
		byID[l.ID] = l
	}
	perFinding := map[uint][]db.FindingLabel{}
	for _, j := range joins {
		if l, ok := byID[j.FindingLabelID]; ok {
			perFinding[j.FindingID] = append(perFinding[j.FindingID], l)
		}
	}
	for i := range findings {
		if findings[i].Labels == nil {
			findings[i].Labels = perFinding[findings[i].ID]
		}
	}
}

// uiRepoRow is the base RepoRow projection (repositoryExport keys plus the
// cheap scalar UI keys). WP-API-3 adds health, status_scan, branches and the
// schedule from its batch loaders without renaming keys.
func uiRepoRow(row repositoryExportRow, repo db.Repository) map[string]any {
	m := repositoryExport(row)
	m["clone_error"] = repo.CloneError
	m["default_branch"] = repo.DefaultBranch
	m["archived"] = repo.Archived
	m["pushed_at"] = repo.PushedAt
	m["description"] = repo.Description
	m["license"] = repo.License
	m["forks"] = repo.Forks
	m["federation_opted_out"] = repo.FederationOptedOut()
	return m
}
