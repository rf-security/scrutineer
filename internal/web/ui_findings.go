package web

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// registerUIFindingRoutes registers the findings read/write routes of the /api/v1/ui surface
// (02-api-plan.md section 3.2 #9-#18, #22, #22a). Owned by WP-API-1. Each route is
// documented in openapi.yaml between the "# --- ui:findings begin/end ---" markers;
// TestOpenAPICoversRegisteredAPIRoutes fails on any undocumented route.
func (s *Server) registerUIFindingRoutes(mux *http.ServeMux) {
	// Reads (#9, #10, #13-#16).
	mux.HandleFunc("GET /ui/findings", s.uiFindingList)
	mux.HandleFunc("GET /ui/findings/{id}", s.uiFindingDetailHandler)
	mux.HandleFunc("GET /ui/findings/{id}/history", s.uiFindingHistory)
	mux.HandleFunc("GET /ui/findings/{id}/notes", s.uiFindingNotes)
	mux.HandleFunc("GET /ui/findings/{id}/communications", s.uiFindingCommunications)
	mux.HandleFunc("GET /ui/findings/{id}/references", s.uiFindingReferences)
	mux.HandleFunc("GET /ui/findings/{id}/reviews", s.uiFindingReviews)
	mux.HandleFunc("GET /ui/findings/{id}/submissions", s.uiFindingSubmissions)
	mux.HandleFunc("GET /ui/findings/{id}/labels", s.uiFindingLabels)
	mux.HandleFunc("GET /ui/findings/{id}/verifications", s.uiFindingVerifications)
	mux.HandleFunc("GET /ui/findings/{id}/observations", s.uiFindingObservations)
	mux.HandleFunc("GET /ui/findings/{id}/attack-paths", s.uiFindingAttackPaths)
	mux.HandleFunc("GET /ui/findings/{id}/remediation", s.uiFindingRemediation)
	mux.HandleFunc("GET /ui/findings/{id}/exposures", s.uiFindingExposures)
	mux.HandleFunc("GET /ui/findings/{id}/migration-guide", s.uiFindingMigrationGuide)

	// Writes (#11, #17, #18).
	mux.HandleFunc("PATCH /ui/findings/{id}", s.uiFindingPatch)
	mux.HandleFunc("POST /ui/findings/{id}/notes", s.uiFindingNoteCreate)
	mux.HandleFunc("POST /ui/findings/{id}/communications", s.uiFindingCommunicationCreate)
	mux.HandleFunc("POST /ui/findings/{id}/references", s.uiFindingReferenceCreate)
	mux.HandleFunc("POST /ui/findings/{id}/reviews", s.uiFindingReviewCreate)
	mux.HandleFunc("PUT /ui/findings/{id}/labels", s.uiFindingLabelsPut)
	mux.HandleFunc("PATCH /ui/findings/{id}/dependents/{dependent_id}/campaign", s.uiFindingCampaignPatch)

	// Bulk (#22) and the label catalogue (#22a).
	mux.HandleFunc("POST /ui/findings/batch", s.uiFindingBatch)
	mux.HandleFunc("GET /ui/labels", s.uiLabelList)
	mux.HandleFunc("POST /ui/labels", s.uiLabelCreate)
	mux.HandleFunc("PATCH /ui/labels/{id}", s.uiLabelPatch)
	mux.HandleFunc("DELETE /ui/labels/{id}", s.uiLabelDelete)
}

// ---------------------------------------------------------------- GET /ui/findings (#9)

const (
	uiFacetStatus   = statusKey
	uiFacetSeverity = "severity"
	uiFacetCategory = "category"
	uiFacetOpen     = "open"
	uiParamCategory = "category"
	uiParamViabilty = "viability"
	uiParamOn       = "1"

	uiKeyURL      = "url"
	uiKeyTitle    = "title"
	uiKeyCWE      = "cwe"
	uiKeyPackages = "packages"
)

// uiFindingListOmit are the prose columns a FindingRow never shows; the list
// skips them so a 200-row page does not drag every disclosure draft along.
// trace stays: title_summary is derived from it.
var uiFindingListOmit = []string{
	"snippet", "disclosure_draft", "mitigation", "mitigation_semgrep", "suggested_fix",
	"boundary", "validation", "prior_art", "reach", "breaking_change_rationale", "exploited_in_wild_evidence",
}

// uiFindingListParams are the parsed, validated filters of GET /ui/findings.
// Filtering itself is delegated to findingsIndexQuery (the HTML list's
// query) so both lists agree; this struct only validates and adds the two
// UI-only filters (repository_id, sub_path).
type uiFindingListParams struct {
	page         listPage
	scanners     bool
	repositoryID uint
	subPath      string
	hasSubPath   bool
	facets       []string
	sort         string
}

// uiFindingStatusFilterValid reports whether status is "", "all" or a lifecycle.
func uiFindingStatusFilterValid(status string) bool {
	return status == "" || status == allStatusValue || slices.Contains(db.FindingLifecycles, db.FindingLifecycle(status))
}

func uiFindingCategoryValid(category string) bool {
	return category == "" || category == UncategorizedCWE || slices.Contains(CWECategories(), category)
}

func parseUIFindingListParams(r *http.Request) (uiFindingListParams, error) {
	var p uiFindingListParams
	var err error
	if p.page, err = parseListPage(r); err != nil {
		return p, err
	}
	q := r.URL.Query()
	if sev := q.Get(uiFacetSeverity); sev != "" && !slices.Contains(db.SeverityLevels, sev) {
		return p, fmt.Errorf("severity must be one of %s, got %q", strings.Join(db.SeverityLevels, ", "), sev)
	}
	if st := q.Get(statusKey); !uiFindingStatusFilterValid(st) {
		return p, fmt.Errorf("status must be empty, %q or a finding lifecycle, got %q", allStatusValue, st)
	}
	if c := q.Get(uiParamCategory); !uiFindingCategoryValid(c) {
		return p, fmt.Errorf("unknown category %q", c)
	}
	if v := q.Get(uiParamViabilty); v != "" && productionViabilityFilter(v) == "" {
		return p, fmt.Errorf("unknown viability %q", v)
	}
	for _, flag := range []string{"missed", "scanners"} {
		if v := q.Get(flag); v != "" && v != uiParamOn && v != "0" {
			return p, fmt.Errorf("%s must be 1 or 0, got %q", flag, v)
		}
	}
	p.scanners = q.Get("scanners") == uiParamOn
	if p.repositoryID, err = uiQueryID(r, "repository_id"); err != nil {
		return p, err
	}
	_, p.hasSubPath = q["sub_path"]
	p.subPath = q.Get("sub_path")
	if p.facets, err = parseUIFindingFacets(q.Get("facets")); err != nil {
		return p, err
	}
	p.sort = q.Get("sort")
	return p, nil
}

func parseUIFindingFacets(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	var out []string
	for _, f := range strings.Split(raw, ",") {
		f = strings.TrimSpace(f)
		switch f {
		case "":
		case uiFacetStatus, uiFacetSeverity, uiFacetCategory:
			if !slices.Contains(out, f) {
				out = append(out, f)
			}
		default:
			return nil, fmt.Errorf("unknown facet %q (want status, severity, category)", f)
		}
	}
	return out, nil
}

// uiFindingScope applies the UI-only filters the HTML list does not have.
func (p uiFindingListParams) scope(q *gorm.DB) *gorm.DB {
	if p.repositoryID != 0 {
		q = q.Where("findings.repository_id = ?", p.repositoryID)
	}
	if p.hasSubPath {
		q = q.Where("findings.sub_path = ?", p.subPath)
	}
	return q
}

// uiRequestWithQuery returns a shallow copy of r whose query has the given
// keys overridden (an empty value deletes the key). findingsIndexQuery reads
// its filters from the request, so a facet's "everything but my own filter"
// query is the same function over an edited query string.
func uiRequestWithQuery(r *http.Request, set map[string]string) *http.Request {
	q := r.URL.Query()
	for k, v := range set {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}
	u := *r.URL
	u.RawQuery = q.Encode()
	r2 := r.Clone(r.Context())
	r2.URL = &u
	return r2
}

// uiFindingListQuery is the filtered (unordered, unpaged) findings query.
func (s *Server) uiFindingListQuery(r *http.Request, p uiFindingListParams) *gorm.DB {
	return p.scope(s.findingsIndexQuery(r, p.scanners, true))
}

func (s *Server) uiFindingList(w http.ResponseWriter, r *http.Request) {
	p, err := parseUIFindingListParams(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	var total int64
	if err := s.uiFindingListQuery(r, p).Count(&total).Error; err != nil {
		uiInternal(w, err)
		return
	}
	q, _, _ := applyFindingsOrder(s.uiFindingListQuery(r, p), p.sort)
	var rows []db.Finding
	if err := q.Omit(uiFindingListOmit...).Limit(p.page.PageSize).Offset(p.page.offset()).Find(&rows).Error; err != nil {
		uiInternal(w, err)
		return
	}
	extra := map[string]any{"counts": s.uiFindingToggleCounts(r, p)}
	if len(p.facets) > 0 {
		facets := make(map[string]map[string]int64, len(p.facets))
		for _, f := range p.facets {
			if facets[f], err = s.uiFindingFacet(r, p, f); err != nil {
				uiInternal(w, err)
				return
			}
		}
		extra["facets"] = facets
	}
	writeListWith(w, s.uiFindingRows(rows), total, p.page, extra)
}

// uiFindingToggleCounts are the missed/scanners toggle badges, computed like
// findingToggleCounts but over the UI scope (repository_id, sub_path).
func (s *Server) uiFindingToggleCounts(r *http.Request, p uiFindingListParams) map[string]int64 {
	var missed, scanners int64
	p.scope(s.findingsIndexQuery(r, p.scanners, false)).Where("missed_count > 0").Count(&missed)
	p.scope(s.findingsIndexQuery(r, true, true)).Where(scannerScanFilter).Count(&scanners)
	return map[string]int64{"missed": missed, "scanners": scanners}
}

// uiFindingFacet counts the current result set grouped by one facet, with
// that facet's own filter removed so chips show what switching would yield.
func (s *Server) uiFindingFacet(r *http.Request, p uiFindingListParams, facet string) (map[string]int64, error) {
	var column string
	var r2 *http.Request
	switch facet {
	case uiFacetStatus:
		column, r2 = "status", uiRequestWithQuery(r, map[string]string{statusKey: allStatusValue})
	case uiFacetSeverity:
		column, r2 = uiFacetSeverity, uiRequestWithQuery(r, map[string]string{uiFacetSeverity: ""})
	default:
		column, r2 = uiKeyCWE, uiRequestWithQuery(r, map[string]string{uiParamCategory: ""})
	}
	var groups []struct {
		FacetKey string
		N        int64
	}
	if err := s.uiFindingListQuery(r2, p).Select("findings." + column + " AS facet_key, COUNT(*) AS n").
		Group("findings." + column).Scan(&groups).Error; err != nil {
		return nil, err
	}
	out := map[string]int64{}
	switch facet {
	case uiFacetStatus:
		out[uiFacetOpen], out[allStatusValue] = 0, 0
		for _, l := range db.FindingLifecycles {
			out[string(l)] = 0
		}
		for _, g := range groups {
			out[g.FacetKey] += g.N
			out[allStatusValue] += g.N
			if !db.FindingLifecycle(g.FacetKey).Closed() {
				out[uiFacetOpen] += g.N
			}
		}
	case uiFacetSeverity:
		for _, l := range db.SeverityLevels {
			out[l] = 0
		}
		for _, g := range groups {
			out[g.FacetKey] += g.N
		}
	default:
		byCWE := uiCWECategoryIndex()
		for _, g := range groups {
			label, ok := byCWE[g.FacetKey]
			if !ok {
				label = UncategorizedCWE
			}
			out[label] += g.N
		}
	}
	return out, nil
}

// uiCWECategoryIndex maps every catalogued CWE id to its View-1400 category
// label, the same membership applyCWECategoryFilter matches on.
func uiCWECategoryIndex() map[string]string {
	out := map[string]string{}
	for _, label := range CWECategories() {
		for _, id := range CWEsInCategory(label) {
			out[id] = label
		}
	}
	return out
}
