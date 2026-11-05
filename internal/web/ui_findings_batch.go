package web

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"scrutineer/internal/db"
)

// POST /ui/findings/batch (#22): bulk edits over a selection, explicitly
// last-write-wins (no If-Match, no `previous`). Per item: the non-status
// fields in one FindingWriteTransaction (applyUIFindingFields), then the
// status transition, then the label delta (read-modify-SetFindingLabels).
// One `finding` event per changed item, one `meta` event if any label was
// created.

const uiBatchMaxIDs = 500

type uiFindingBatchBody struct {
	IDs    []uint            `json:"ids"`
	Set    map[string]string `json:"set"`
	Labels *struct {
		Add    []string `json:"add"`
		Remove []string `json:"remove"`
	} `json:"labels"`
	Verdict  string `json:"verdict"`
	Reason   string `json:"reason"`
	Reviewer string `json:"reviewer"`
	By       string `json:"by"`
}

// uiFindingBatchPlan is a validated batch body.
type uiFindingBatchPlan struct {
	ids          []uint
	fields       map[string]string
	status       string
	hasStatus    bool
	addLabels    []string
	removeLabels []string
	verdict      string
	reason       string
	reviewer     string
	by           string
}

// uiBatchSetFields are the `set` keys the batch accepts (02 #22).
var uiBatchSetFields = []string{statusKey, uiFacetSeverity, "assignee", "resolution", uiKeyCWE}

func parseUIFindingBatch(b uiFindingBatchBody) (uiFindingBatchPlan, error) {
	p := uiFindingBatchPlan{verdict: b.Verdict, reason: b.Reason, reviewer: b.Reviewer, by: strings.TrimSpace(b.By)}
	errs := uiFieldErrors{}
	switch {
	case len(b.IDs) == 0:
		errs["ids"] = "at least one id is required"
	case len(b.IDs) > uiBatchMaxIDs:
		errs["ids"] = fmt.Sprintf("at most %d ids per batch", uiBatchMaxIDs)
	}
	seen := map[uint]bool{}
	for _, id := range b.IDs {
		if id != 0 && !seen[id] {
			seen[id] = true
			p.ids = append(p.ids, id)
		}
	}
	fields := map[string]string{}
	for k, v := range b.Set {
		switch {
		case !slices.Contains(uiBatchSetFields, k):
			errs["set."+k] = "not settable in a batch"
		case k == statusKey:
			p.status, p.hasStatus = strings.TrimSpace(v), true
			if !slices.Contains(db.FindingLifecycles, db.FindingLifecycle(p.status)) {
				errs["set.status"] = "not a finding lifecycle"
			}
		default:
			fields[k] = v
		}
	}
	if norm, err := normalizeUIFindingFields(fields); err != nil {
		for k, v := range apiFieldsError(err) {
			errs["set."+k] = v
		}
	} else {
		p.fields = norm
	}
	if b.Labels != nil {
		var err error
		if p.addLabels, err = normalizeUILabelNames(b.Labels.Add); err != nil {
			errs["labels.add"] = err.Error()
		}
		if p.removeLabels, err = normalizeUILabelNames(b.Labels.Remove); err != nil {
			errs["labels.remove"] = err.Error()
		}
	}
	if len(errs) == 0 && len(p.fields) == 0 && !p.hasStatus && len(p.addLabels)+len(p.removeLabels) == 0 {
		errs["set"] = "nothing to change: give set and/or labels"
	}
	if len(errs) > 0 {
		return p, errs
	}
	return p, nil
}

// uiBatchFindingStatus applies one status transition with the HTML
// findingStatus rules: rejected goes through db.RejectFinding (verdict and
// reason required), ready needs a saved disclosure draft, reported runs the
// federation claim gate first (a recorded claim refuses the item with
// ErrFederationClaimPending; resubmitting goes through, as on the page).
// Returns whether the status changed.
//
// TODO(WP-API-2): once applyFindingStatus is extracted from
// server.go:findingStatus, call it here instead of mirroring the rules.
func (s *Server) uiBatchFindingStatus(ctx context.Context, f db.Finding, p uiFindingBatchPlan) (bool, error) {
	status := db.FindingLifecycle(p.status)
	gdb := s.DB.WithContext(ctx)
	if status == db.FindingRejected {
		if err := db.RejectFinding(gdb, f.ID, p.verdict, p.reason, p.reviewer); err != nil {
			return false, err
		}
		return true, nil
	}
	if f.Status == status {
		return false, nil
	}
	if status == db.FindingReady && strings.TrimSpace(f.DisclosureDraft) == "" {
		return false, uiFieldErrors{statusKey: "a saved disclosure draft is required before marking ready"}
	}
	if status == db.FindingReported {
		claims, err := s.claimPeerHold(ctx, f)
		if err != nil {
			return false, err
		}
		if claims != "" {
			return false, ErrFederationClaimPending
		}
	}
	if err := db.WriteFindingField(gdb, f.ID, statusKey, string(status), db.SourceAnalyst, p.by); err != nil {
		return false, err
	}
	return true, nil
}

// uiBatchLabels applies the add/remove delta to one finding's labels.
func (s *Server) uiBatchLabels(ctx context.Context, f db.Finding, p uiFindingBatchPlan) (changed, created bool, err error) {
	old := make([]string, 0, len(f.Labels))
	for _, l := range f.Labels {
		old = append(old, l.Name)
	}
	names := slices.DeleteFunc(slices.Clone(old), func(n string) bool { return slices.Contains(p.removeLabels, n) })
	names = append(names, p.addLabels...)
	slices.Sort(old)
	slices.Sort(names)
	names = slices.Compact(names)
	if slices.Equal(old, names) {
		return false, false, nil
	}
	created, err = s.uiSetFindingLabels(ctx, f.ID, names, p.by)
	return err == nil, created, err
}

// uiBatchItem is one per-item result.
type uiBatchItem struct {
	ID    uint   `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Code  string `json:"code,omitempty"`
}

// applyUIFindingBatchItem runs the plan for one finding and returns the
// changed event fields and whether a label was created.
func (s *Server) applyUIFindingBatchItem(ctx context.Context, id uint, p uiFindingBatchPlan) (db.Finding, []string, bool, error) {
	var f db.Finding
	if err := s.DB.WithContext(ctx).Preload("Labels").First(&f, id).Error; err != nil {
		return f, nil, false, err
	}
	var changed []string
	if len(p.fields) > 0 {
		written, err := s.applyUIFindingFields(ctx, id, p.fields, nil, f.UpdatedAt, false, p.by)
		if err != nil {
			return f, nil, false, err
		}
		changed = append(changed, written...)
	}
	if p.hasStatus {
		ok, err := s.uiBatchFindingStatus(ctx, f, p)
		if err != nil {
			return f, changed, false, err
		}
		if ok {
			changed = append(changed, statusKey)
		}
	}
	created := false
	if len(p.addLabels)+len(p.removeLabels) > 0 {
		ok, c, err := s.uiBatchLabels(ctx, f, p)
		if err != nil {
			return f, changed, false, err
		}
		if ok {
			changed = append(changed, uiEventLabels)
		}
		created = c
	}
	return f, changed, created, nil
}

func (s *Server) uiFindingBatch(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeUIFindingBody[uiFindingBatchBody](w, r)
	if !ok {
		return
	}
	p, err := parseUIFindingBatch(body)
	if err != nil {
		writeUIFields(w, err)
		return
	}
	results := make([]uiBatchItem, 0, len(p.ids))
	updated, failed := 0, 0
	anyCreated := false
	for _, id := range p.ids {
		f, changed, created, err := s.applyUIFindingBatchItem(r.Context(), id, p)
		anyCreated = anyCreated || created
		// Fields written before a later step failed are still committed, so
		// they are announced either way.
		if len(changed) > 0 {
			s.publishFinding(id, f.RepositoryID, uiChangeUpdated, changed...)
		}
		if err != nil {
			_, code := uiFindingErrStatus(err)
			results = append(results, uiBatchItem{ID: id, Error: err.Error(), Code: code})
			failed++
			continue
		}
		results = append(results, uiBatchItem{ID: id, OK: true})
		updated++
	}
	if anyCreated {
		s.publishMeta(uiEventLabels)
	}
	writeUIJSON(w, http.StatusOK, map[string]any{"results": results, "updated": updated, "failed": failed})
}
