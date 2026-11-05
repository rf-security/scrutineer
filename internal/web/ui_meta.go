package web

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"scrutineer/internal/config"
	"scrutineer/internal/db"
)

// Vocabularies for the SPA (02-api-plan.md section 3.1 #5, #5a, #6). Enum
// values are the db constants; labels are display text, so the SPA never
// hard-codes either.

const (
	uiMetaMaxAge     = "private, max-age=3600"
	uiCWEDefaultLim  = 20
	uiCWEMaxLimit    = 200
	labelValueKey    = "value"
	labelLabelKey    = "label"
	uiAssistantRole  = "assistant"
	uiUnknownLabel   = "Unknown"
	uiNoneLabel      = "None"
	uiSkillSourceKey = "source"
)

type labelled struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// uiRepoTab is one canonical repository tab and its presentation group
// (01-feature-inventory.md section 31, normative).
type uiRepoTab struct {
	Name  string `json:"name"`
	Group string `json:"group"`
}

var uiRepoTabs = []uiRepoTab{
	{"summary", "Overview"},
	{uiKeyFindings, "Findings"}, {"scanners", "Findings"},
	{"scans", "Scans"},
	{"packages", "Supply chain"}, {"dependencies", "Supply chain"}, {"dependents", "Supply chain"},
	{"advisories", "Supply chain"}, {"alternatives", "Supply chain"}, {"maintainers", "Supply chain"},
	{"compliance", "Supply chain"},
	{"threat-model", "Analysis"}, {"workbench", "Analysis"}, {"benchmark", "Analysis"},
	{"scan-config", "Config"}, {"data", "Config"},
	{"chat", "Chat"},
}

// uiLegacyRepoTabs maps the old #rtN hashes to canonical tabs (01 section 30;
// #rt15 was both Alternatives and Chat and resolves to alternatives).
var uiLegacyRepoTabs = map[string]string{
	"rt1": "summary", "rt2": "data", "rt3": "scans", "rt4": uiKeyFindings, "rt5": "dependencies",
	"rt6": "packages", "rt7": "dependents", "rt8": "advisories", "rt9": "maintainers",
	"rt10": "threat-model", "rt11": "scanners", "rt12": "workbench", "rt13": "benchmark",
	"rt14": "scan-config", "rt15": "alternatives", "rt16": "compliance",
}

// humanize turns a snake/kebab token into a sentence-case label.
func humanize(v string) string {
	if v == "" {
		return uiNoneLabel
	}
	v = strings.NewReplacer("_", " ", "-", " ").Replace(v)
	return strings.ToUpper(v[:1]) + v[1:]
}

func labelledList[T ~string](values []T) []labelled {
	out := make([]labelled, len(values))
	for i, v := range values {
		out[i] = labelled{Value: string(v), Label: humanize(string(v))}
	}
	return out
}

func uiFindingStatuses() []map[string]any {
	out := make([]map[string]any, len(db.FindingLifecycles))
	for i, st := range db.FindingLifecycles {
		out[i] = map[string]any{labelValueKey: string(st), labelLabelKey: humanize(string(st)), "closed": st.Closed()}
	}
	return out
}

func uiSeverities() []labelled {
	out := make([]labelled, 0, len(db.SeverityLevels))
	for i := len(db.SeverityLevels) - 1; i >= 0; i-- {
		v := db.SeverityLevels[i]
		out = append(out, labelled{Value: v, Label: displaySeverity(v)})
	}
	return out
}

func uiCWECategories() []labelled {
	cats := CWECategories()
	out := make([]labelled, 0, len(cats)+1)
	for _, c := range cats {
		out = append(out, labelled{Value: c, Label: CategoryLabel(c)})
	}
	return append(out, labelled{Value: UncategorizedCWE, Label: UncategorizedCWE})
}

func uiEfforts() []labelled {
	out := make([]labelled, len(Efforts))
	for i, e := range Efforts {
		out[i] = labelled(e)
	}
	return out
}

func uiModelTiers() []string {
	out := make([]string, len(ModelTiers))
	for i, t := range ModelTiers {
		out[i] = t.Value
	}
	return out
}

// uiMetaBody is the static vocabulary document.
func uiMetaBody() map[string]any {
	return map[string]any{
		"finding_statuses": uiFindingStatuses(),
		"severities":       uiSeverities(),
		"scan_statuses": labelledList([]db.ScanStatus{db.ScanQueued, db.ScanRunning, db.ScanPaused, db.ScanDone,
			db.ScanFailed, db.ScanSkipped, db.ScanCancelled}),
		"cwe_categories": uiCWECategories(),
		"themes":         config.Themes,
		"resolutions": labelledList([]db.FindingResolution{"", db.ResolutionFix, db.ResolutionMigrate,
			db.ResolutionWorkaround, db.ResolutionAdopt, db.ResolutionWontfix}),
		"campaign_statuses":        labelledList(db.DependentCampaignStatuses),
		"review_verdicts":          labelledList([]string{"true_positive", "false_positive", "already_fixed", "uncertain"}),
		"communication_channels":   labelledList([]string{"email", "ghsa", "issue", "pr", "direct", "registry"}),
		"communication_directions": labelledList([]string{"outbound", "inbound"}),
		"offered_help": []labelled{{"", "No offer"}, {"pr", "Offered PR"}, {"funding", "Offered funding"},
			{"adoption", "Offered adoption"}},
		"efforts":           uiEfforts(),
		"model_tiers":       uiModelTiers(),
		"exploited_in_wild": []labelled{{"", uiUnknownLabel}, {"yes", "Yes"}, {"no", "No"}},
		"page_size_default": uiDefaultPageSize,
		"page_size_max":     uiMaxPageSize,
		"repo_tabs":         map[string]any{"tabs": uiRepoTabs, "legacy": uiLegacyRepoTabs},
	}
}

func (s *Server) uiMeta(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set(cacheControlHeader, uiMetaMaxAge)
	writeUIJSON(w, http.StatusOK, uiMetaBody())
}

// uiSkillRow is the UISkill projection (02 #85).
func uiSkillRow(sk db.Skill) map[string]any {
	return map[string]any{
		"id": sk.ID, uiKeyName: sk.Name, "description": sk.Description, "output_kind": sk.OutputKind,
		"output_file": sk.OutputFile, "max_turns": sk.MaxTurns, uiKeyModel: sk.Model, "version": sk.Version,
		"active": sk.Active, uiSkillSourceKey: sk.Source, "path": sk.SourcePath, "license": sk.License,
		"compatibility": sk.Compatibility, "requires_remote": sk.RequiresRemote,
		uiKeyCreatedAt: sk.CreatedAt, "updated_at": sk.UpdatedAt,
	}
}

func (s *Server) uiMetaDynamic(w http.ResponseWriter, _ *http.Request) {
	var labels []db.FindingLabel
	if err := s.DB.Order(uiKeyName).Find(&labels).Error; err != nil {
		uiInternal(w, err)
		return
	}
	labelRows := make([]map[string]any, len(labels))
	for i, l := range labels {
		labelRows[i] = uiLabel(l)
	}
	var skills []db.Skill
	s.DB.Omit("body", "schema_json", "metadata").Where("active = ?", true).Order(uiKeyName).Find(&skills)
	skillRows := make([]map[string]any, len(skills))
	for i, sk := range skills {
		skillRows[i] = uiSkillRow(sk)
	}
	models := make([]map[string]string, len(Models))
	for i, m := range Models {
		models[i] = map[string]string{labelValueKey: m.ID, labelLabelKey: m.Name, "tier": m.Tier}
	}
	egress := s.ScanEgressPolicies
	if egress == nil {
		egress = []string{}
	}
	downgraded, overage := false, false
	if s.Worker != nil {
		downgraded, overage = s.Worker.ShouldDowngradeModel(), s.Worker.ShouldPauseOnOverage()
	}
	writeUIJSON(w, http.StatusOK, map[string]any{
		"labels":          labelRows,
		"skills_active":   skillRows,
		"models":          models,
		"egress_policies": egress,
		"features": map[string]bool{
			"vince": s.VINCE.Enabled(), "akrites": s.Akrites.Enabled(), "federation": s.FederationSalt != "",
			"ecosystems_enrichment": s.ecosystemsEnrichment, "chat": s.chatRunner != nil,
		},
		"runner": map[string]bool{"model_downgraded": downgraded, "overage_paused": overage},
	})
}

// uiMetaCWE searches the CWE catalogue: an id ("79", "CWE-79") matches
// exactly, otherwise q is a case-insensitive substring of the name across the
// View-1400-mapped entries.
func (s *Server) uiMetaCWE(w http.ResponseWriter, r *http.Request) {
	limit := uiCWEDefaultLim
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > uiCWEMaxLimit {
			uiBadParam(w, "limit must be 1.."+strconv.Itoa(uiCWEMaxLimit))
			return
		}
		limit = n
	}
	writeUIJSON(w, http.StatusOK, searchCWE(strings.TrimSpace(r.URL.Query().Get("q")), limit))
}

func cweEntryRow(id string, e CWE) map[string]string {
	return map[string]string{"id": id, uiKeyName: e.Name, "category": e.Category}
}

func searchCWE(q string, limit int) []map[string]string {
	out := make([]map[string]string, 0)
	seen := map[string]bool{}
	if id, e, ok := LookupCWE(q); ok {
		out = append(out, cweEntryRow(id, e))
		seen[id] = true
	}
	needle := strings.ToLower(q)
	ids := make([]string, 0)
	for _, cat := range CWECategories() {
		ids = append(ids, CWEsInCategory(cat)...)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if len(out) >= limit {
			break
		}
		if seen[id] {
			continue
		}
		_, e, ok := LookupCWE(id)
		if !ok || (needle != "" && !strings.Contains(strings.ToLower(e.Name), needle) && !strings.Contains(strings.ToLower(id), needle)) {
			continue
		}
		seen[id] = true
		out = append(out, cweEntryRow(id, e))
	}
	return out
}
