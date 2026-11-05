package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// Scan actions of the /api/v1/ui surface (02-api-plan.md #60, #61, #61a):
// single-scan cancel/resume/retry, the filter-based queue bulk actions and
// the selection batch. Each is a thin wrapper over the helper the HTML
// handler calls (scans.go), so guards and side effects are identical.

const (
	uiScanActionCancel = "cancel"
	uiScanActionResume = "resume"
	uiScanActionRetry  = "retry"

	// uiScanBatchMax caps one POST /ui/scans/batch selection.
	uiScanBatchMax = 200
)

// uiScanActions is the set the {action} path value and batch `action` accept.
var uiScanActions = map[string]bool{uiScanActionCancel: true, uiScanActionResume: true, uiScanActionRetry: true}

// uiScanActionOmit are the blobs a scan action never reads. A retry needs
// import_payload (ingest scans re-stage it), so it is not omitted.
var uiScanActionOmit = []string{"log", "report", "prompt", "refusal_audit", "api_token", "recipe"}

// uiScanActionOutcome is the result of one scan action: on success scanID is
// the new attempt (retry) or the scan itself; on failure status/code/msg are
// the error envelope.
type uiScanActionOutcome struct {
	scanID uint
	status int
	code   string
	msg    string
}

func (o uiScanActionOutcome) ok() bool { return o.status == 0 }

func uiScanActionFailed(status int, code, msg string) uiScanActionOutcome {
	return uiScanActionOutcome{status: status, code: code, msg: msg}
}

// runUIScanAction loads scan id and runs action on it with the HTML
// handler's guards: 404 missing, 400 wrong state (or no skill to retry), and
// mapEnqueueErr's statuses for resume/retry failures.
func (s *Server) runUIScanAction(ctx context.Context, action string, id uint) uiScanActionOutcome {
	var scan db.Scan
	if err := s.DB.Omit(uiScanActionOmit...).First(&scan, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return uiScanActionFailed(http.StatusNotFound, uiCodeNotFound, uiScanWhat+" not found")
		}
		return uiScanActionFailed(http.StatusInternalServerError, uiCodeInternal, err.Error())
	}
	var err error
	newID := scan.ID
	switch action {
	case uiScanActionCancel:
		err = s.cancelScanByUser(&scan)
	case uiScanActionResume:
		err = s.resumePausedScan(ctx, &scan)
	case uiScanActionRetry:
		newID, err = s.retryScan(ctx, scan)
	default:
		return uiScanActionFailed(http.StatusBadRequest, uiCodeBadParam, "unknown action "+action)
	}
	if err == nil {
		return uiScanActionOutcome{scanID: newID}
	}
	if errors.Is(err, errScanFinished) || errors.Is(err, errScanPaused) ||
		errors.Is(err, errScanNotPaused) || errors.Is(err, errScanNotRetryable) {
		return uiScanActionFailed(http.StatusBadRequest, uiCodeBadParam, err.Error())
	}
	status, code := enqueueErrStatus(err)
	return uiScanActionFailed(status, code, err.Error())
}

// uiScanAction is POST /api/v1/ui/scans/{id}/actions/{cancel|resume|retry}:
// 200 ScanRow for cancel/resume, 202 {scan_id} for retry.
func (s *Server) uiScanAction(w http.ResponseWriter, r *http.Request) {
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return
	}
	action := r.PathValue("action")
	if !uiScanActions[action] {
		uiBadParam(w, "unknown action "+action)
		return
	}
	out := s.runUIScanAction(r.Context(), action, id)
	if !out.ok() {
		writeUIError(w, out.status, out.code, out.msg, nil)
		return
	}
	if action == uiScanActionRetry {
		enqueueResult(w, out.scanID)
		return
	}
	row, err := s.loadUIScanRow(id)
	if err != nil {
		uiDBError(w, err, uiScanWhat)
		return
	}
	writeUIJSON(w, http.StatusOK, row)
}

// ---------------------------------------------------------------- bulk

// uiScanBulkRequest is the ScanBulkRequest body of the filter-based queue
// actions; each action reads the keys it supports.
type uiScanBulkRequest struct {
	RepositoryID uint   `json:"repository_id"`
	Skill        string `json:"skill"`
	Completeness string `json:"completeness"`
	Group        string `json:"group"`
}

// uiScanBulkResult is ScanBulkResult.
type uiScanBulkResult struct {
	Affected int    `json:"affected"`
	Retried  *int   `json:"retried,omitempty"`
	Skipped  *int   `json:"skipped,omitempty"`
	Errored  *int   `json:"errored,omitempty"`
	ScanIDs  []uint `json:"scan_ids,omitempty"`
}

// decodeUIScanBody decodes an optional JSON body (empty = zero value) capped
// at apiMaxBody, writing a 400 on malformed JSON.
func decodeUIScanBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, apiMaxBody)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil && !errors.Is(err, io.EOF) {
		uiBadParam(w, "invalid JSON request body")
		return false
	}
	return true
}

// uiScansPauseQueued is POST /api/v1/ui/scans/actions/pause-queued.
func (s *Server) uiScansPauseQueued(w http.ResponseWriter, r *http.Request) {
	var req uiScanBulkRequest
	if !decodeUIScanBody(w, r, &req) {
		return
	}
	changed, err := s.pauseQueuedScans()
	if err != nil {
		uiInternal(w, err)
		return
	}
	writeUIJSON(w, http.StatusOK, uiScanBulkResult{Affected: len(changed)})
}

// uiScansResumePaused is POST /api/v1/ui/scans/actions/resume-paused
// {repository_id?}. It re-enqueues the paused scans.
func (s *Server) uiScansResumePaused(w http.ResponseWriter, r *http.Request) {
	var req uiScanBulkRequest
	if !decodeUIScanBody(w, r, &req) {
		return
	}
	resumed, errored, err := s.resumePausedScans(r.Context(), req.RepositoryID)
	if err != nil {
		uiInternal(w, err)
		return
	}
	writeUIJSON(w, http.StatusOK, uiScanBulkResult{Affected: resumed, Errored: &errored})
}

// uiScansRetryFailed is POST /api/v1/ui/scans/actions/retry-failed
// {repository_id?, skill?, completeness?, group?}. It enqueues model work.
func (s *Server) uiScansRetryFailed(w http.ResponseWriter, r *http.Request) {
	var req uiScanBulkRequest
	if !decodeUIScanBody(w, r, &req) {
		return
	}
	completeness, err := parseScanCompletenessFilter(req.Completeness)
	if err != nil {
		writeUIError(w, http.StatusUnprocessableEntity, uiCodeValidationFailed, err.Error(),
			map[string]string{"completeness": err.Error()})
		return
	}
	res, err := s.retryFailedScans(r.Context(), retryFailedFilter{
		skill: parseScanSkillFilter(req.Skill), completeness: completeness, group: req.Group, repositoryID: req.RepositoryID,
	})
	if err != nil {
		uiInternal(w, err)
		return
	}
	ids := res.scanIDs
	if ids == nil {
		ids = []uint{}
	}
	writeUIJSON(w, http.StatusOK, uiScanBulkResult{
		Affected: res.retried, Retried: &res.retried, Skipped: &res.skipped, Errored: &res.errored, ScanIDs: ids,
	})
}

// uiScansCancelAll is POST /api/v1/ui/scans/actions/cancel-all
// {repository_id} (required).
func (s *Server) uiScansCancelAll(w http.ResponseWriter, r *http.Request) {
	var req uiScanBulkRequest
	if !decodeUIScanBody(w, r, &req) {
		return
	}
	if req.RepositoryID == 0 {
		writeUIError(w, http.StatusUnprocessableEntity, uiCodeValidationFailed, "repository_id is required",
			map[string]string{repositoryIDKey: "required"})
		return
	}
	cancelled, err := s.cancelAllScans(req.RepositoryID)
	if err != nil {
		uiInternal(w, err)
		return
	}
	writeUIJSON(w, http.StatusOK, uiScanBulkResult{Affected: cancelled})
}

// ---------------------------------------------------------------- batch

// uiScanBatchRequest is ScanBatchRequest.
type uiScanBatchRequest struct {
	IDs    []uint `json:"ids"`
	Action string `json:"action"`
}

// uiScanBatchItem is one BatchItemResult.
type uiScanBatchItem struct {
	ID     uint   `json:"id"`
	OK     bool   `json:"ok"`
	ScanID uint   `json:"scan_id,omitempty"`
	Error  string `json:"error,omitempty"`
	Code   string `json:"code,omitempty"`
}

func (req uiScanBatchRequest) validate() error {
	fields := uiFieldErrors{}
	if !uiScanActions[req.Action] {
		fields["action"] = "must be cancel, resume or retry"
	}
	switch {
	case len(req.IDs) == 0:
		fields["ids"] = "required"
	case len(req.IDs) > uiScanBatchMax:
		fields["ids"] = "at most 200 ids"
	}
	for _, id := range req.IDs {
		if id == 0 {
			fields["ids"] = "ids must be positive"
		}
	}
	if len(fields) > 0 {
		return fields
	}
	return nil
}

// uiScansBatch is POST /api/v1/ui/scans/batch {ids, action}: the single-scan
// action per id (same guards and status codes per item), duplicates run once.
// Every item publishes what the single action does; the queue counters are
// debounced into one `queue` event, and one instance-wide `scans` refetch is
// sent when anything changed.
func (s *Server) uiScansBatch(w http.ResponseWriter, r *http.Request) {
	var req uiScanBatchRequest
	if !decodeUIScanBody(w, r, &req) {
		return
	}
	if err := req.validate(); err != nil {
		writeUIFields(w, err)
		return
	}
	results := make([]uiScanBatchItem, 0, len(req.IDs))
	seen := make(map[uint]bool, len(req.IDs))
	affected := 0
	for _, id := range req.IDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		out := s.runUIScanAction(r.Context(), req.Action, id)
		item := uiScanBatchItem{ID: id, OK: out.ok()}
		if out.ok() {
			affected++
			if req.Action == uiScanActionRetry {
				item.ScanID = out.scanID
			}
		} else {
			item.Error, item.Code = out.msg, out.code
		}
		results = append(results, item)
	}
	if affected > 0 {
		s.publishScanList(0)
	}
	writeUIJSON(w, http.StatusOK, map[string]any{"results": results, "affected": affected})
}
