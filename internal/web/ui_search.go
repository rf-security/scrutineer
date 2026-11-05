package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// GET /api/v1/ui/search: the command palette's grouped search (02 #7). Each
// group is one COUNT plus one LIMITed query; refs carry ids, never hrefs.

const (
	uiSearchDefaultLimit = 5
	uiSearchMaxLimit     = 50
	uiSearchMaxQuery     = 200
	searchSep            = " · "
)

// searchRef is one palette hit.
type searchRef struct {
	Kind  string `json:"kind"`
	ID    any    `json:"id"`
	Label string `json:"label"`
	Sub   string `json:"sub"`
}

type searchGroup struct {
	Items []searchRef `json:"items"`
	Total int64       `json:"total"`
}

// searchTerm is the parsed query: a LIKE pattern plus the id a numeric query
// names ("123", "#123" for findings, "s4753" for scans).
type searchTerm struct {
	like      string
	id        uint
	scanID    uint
	findingID uint
}

func parseSearchTerm(q string) searchTerm {
	t := searchTerm{like: "%" + escapeLike(q) + "%"}
	parse := func(v string) uint {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0
		}
		return uint(n)
	}
	switch {
	case strings.HasPrefix(q, "#"):
		t.findingID = parse(q[1:])
	case strings.HasPrefix(strings.ToLower(q), "s") && parse(q[1:]) != 0:
		t.scanID = parse(q[1:])
	default:
		t.id = parse(q)
		t.findingID, t.scanID = t.id, t.id
	}
	return t
}

// escapeLike escapes LIKE wildcards so a literal % or _ in q matches itself.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(s)
}

// likeAny builds "(LOWER(a) LIKE LOWER(?) ESCAPE '\' OR ...)" over cols.
func likeAny(cols ...string) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = "LOWER(" + c + `) LIKE LOWER(?) ESCAPE '\'`
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

func repeatArg(v any, n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// reusable lets one filtered query run both the COUNT and the page fetch;
// without a new session GORM would carry the count's clauses into the fetch.
func reusable(q *gorm.DB) *gorm.DB { return q.Session(&gorm.Session{}) }

// withID ORs an exact id match onto a LIKE clause when the term names one.
func withID(q *gorm.DB, clause string, args []any, idCol string, id uint) *gorm.DB {
	if id != 0 {
		return q.Where(clause+" OR "+idCol+" = ?", append(args, id)...)
	}
	return q.Where(clause, args...)
}

func (s *Server) uiSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > uiSearchMaxQuery {
		uiBadParam(w, fmt.Sprintf("q must be at most %d characters", uiSearchMaxQuery))
		return
	}
	limit := uiSearchDefaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > uiSearchMaxLimit {
			uiBadParam(w, fmt.Sprintf("limit must be 1..%d", uiSearchMaxLimit))
			return
		}
		limit = n
	}
	groups := map[string]searchGroup{}
	for _, g := range []string{"repositories", uiKeyFindings, "scans", "packages", "orgs", "maintainers", uiKeyAdvisories, "skills", "sboms"} {
		groups[g] = searchGroup{Items: []searchRef{}}
	}
	if q != "" {
		t := parseSearchTerm(q)
		groups["repositories"] = s.searchRepositories(t, limit)
		groups[uiKeyFindings] = s.searchFindings(t, limit)
		groups["scans"] = s.searchScans(t, limit)
		groups["packages"] = s.searchPackages(t, limit)
		groups["orgs"] = s.searchOrgs(t, limit)
		groups["maintainers"] = s.searchMaintainers(t, limit)
		groups[uiKeyAdvisories] = s.searchAdvisories(t, limit)
		groups["skills"] = s.searchSkills(t, limit)
		groups["sboms"] = s.searchSBOMs(t, limit)
	}
	writeUIJSON(w, http.StatusOK, map[string]any{"groups": groups})
}

func (s *Server) searchRepositories(t searchTerm, limit int) searchGroup {
	cols := []string{uiKeyName, "full_name", uiKeyURL}
	q := reusable(withID(s.DB.Model(&db.Repository{}), likeAny(cols...), repeatArg(t.like, len(cols)), "id", t.id))
	var g searchGroup
	q.Count(&g.Total)
	var rows []db.Repository
	q.Select("id", uiKeyName, "full_name", uiKeyURL).Order(uiKeyName).Limit(limit).Find(&rows)
	g.Items = make([]searchRef, len(rows))
	for i, r := range rows {
		label := r.FullName
		if label == "" {
			label = r.Name
		}
		g.Items[i] = searchRef{Kind: uiKeyRepository, ID: r.ID, Label: label, Sub: r.URL}
	}
	return g
}

func (s *Server) searchFindings(t searchTerm, limit int) searchGroup {
	cols := []string{"title", "cve_id", "ghsa_id", "location"}
	q := reusable(withID(s.DB.Model(&db.Finding{}), likeAny(cols...), repeatArg(t.like, len(cols)), "id", t.findingID))
	var g searchGroup
	q.Count(&g.Total)
	var rows []db.Finding
	q.Select("id", "title", uiKeySeverity, "status").Order("id desc").Limit(limit).Find(&rows)
	g.Items = make([]searchRef, len(rows))
	for i, f := range rows {
		g.Items[i] = searchRef{Kind: "finding", ID: f.ID, Label: f.Title, Sub: f.Severity + searchSep + string(f.Status)}
	}
	return g
}

func (s *Server) searchScans(t searchTerm, limit int) searchGroup {
	q := reusable(withID(s.DB.Model(&db.Scan{}), likeAny("skill_name"), []any{t.like}, "id", t.scanID))
	var g searchGroup
	q.Count(&g.Total)
	var rows []db.Scan
	q.Select("id", "skill_name", "kind", "status").Order("id desc").Limit(limit).Find(&rows)
	g.Items = make([]searchRef, len(rows))
	for i, sc := range rows {
		name := sc.SkillName
		if name == "" {
			name = sc.Kind
		}
		g.Items[i] = searchRef{Kind: "scan", ID: sc.ID, Label: fmt.Sprintf("#%d %s", sc.ID, name), Sub: string(sc.Status)}
	}
	return g
}

func (s *Server) searchPackages(t searchTerm, limit int) searchGroup {
	cols := []string{uiKeyName, "p_url"}
	q := reusable(s.DB.Model(&db.Package{}).Where(likeAny(cols...), repeatArg(t.like, len(cols))...))
	var g searchGroup
	q.Count(&g.Total)
	var rows []db.Package
	q.Select("id", uiKeyName, uiKeyEcosystem).Order(uiKeyName).Limit(limit).Find(&rows)
	g.Items = make([]searchRef, len(rows))
	for i, p := range rows {
		g.Items[i] = searchRef{Kind: "package", ID: p.ID, Label: p.Name, Sub: p.Ecosystem}
	}
	return g
}

func (s *Server) searchOrgs(t searchTerm, limit int) searchGroup {
	q := reusable(s.DB.Model(&db.Repository{}).Where("owner <> ''").Where(likeAny("owner"), t.like))
	var g searchGroup
	q.Distinct("owner").Count(&g.Total)
	var owners []struct {
		Owner string
		N     int64
	}
	q.Select("owner, COUNT(*) AS n").Group("owner").Order("owner").Limit(limit).Scan(&owners)
	g.Items = make([]searchRef, len(owners))
	for i, o := range owners {
		g.Items[i] = searchRef{Kind: "org", ID: o.Owner, Label: o.Owner, Sub: fmt.Sprintf("%d repositories", o.N)}
	}
	return g
}

func (s *Server) searchMaintainers(t searchTerm, limit int) searchGroup {
	cols := []string{"login", uiKeyName, "email"}
	q := reusable(s.DB.Model(&db.Maintainer{}).Where(likeAny(cols...), repeatArg(t.like, len(cols))...))
	var g searchGroup
	q.Count(&g.Total)
	var rows []db.Maintainer
	q.Select("id", "login", uiKeyName, "email").Order("login").Limit(limit).Find(&rows)
	g.Items = make([]searchRef, len(rows))
	for i, m := range rows {
		g.Items[i] = searchRef{Kind: "maintainer", ID: m.ID, Label: m.Login, Sub: strings.TrimSpace(m.Name + " " + m.Email)}
	}
	return g
}

func (s *Server) searchAdvisories(t searchTerm, limit int) searchGroup {
	cols := []string{"title", "uuid", "packages"}
	q := reusable(s.DB.Model(&db.Advisory{}).Where(likeAny(cols...), repeatArg(t.like, len(cols))...))
	var g searchGroup
	q.Count(&g.Total)
	var rows []db.Advisory
	q.Select("id", "title", "uuid", uiKeySeverity).Order("id desc").Limit(limit).Find(&rows)
	g.Items = make([]searchRef, len(rows))
	for i, a := range rows {
		g.Items[i] = searchRef{Kind: "advisory", ID: a.ID, Label: a.Title, Sub: strings.TrimSpace(a.Severity + searchSep + a.UUID)}
	}
	return g
}

func (s *Server) searchSkills(t searchTerm, limit int) searchGroup {
	cols := []string{uiKeyName, "description"}
	q := reusable(s.DB.Model(&db.Skill{}).Where(likeAny(cols...), repeatArg(t.like, len(cols))...))
	var g searchGroup
	q.Count(&g.Total)
	var rows []db.Skill
	q.Select("id", uiKeyName, "output_kind", "active").Order("active desc, name").Limit(limit).Find(&rows)
	g.Items = make([]searchRef, len(rows))
	for i, sk := range rows {
		sub := sk.OutputKind
		if !sk.Active {
			sub += searchSep + "inactive"
		}
		g.Items[i] = searchRef{Kind: "skill", ID: sk.ID, Label: sk.Name, Sub: sub}
	}
	return g
}

func (s *Server) searchSBOMs(t searchTerm, limit int) searchGroup {
	cols := []string{uiKeyName, "filename"}
	q := reusable(s.DB.Model(&db.SBOMUpload{}).Where(likeAny(cols...), repeatArg(t.like, len(cols))...))
	var g searchGroup
	q.Count(&g.Total)
	var rows []db.SBOMUpload
	q.Select("id", uiKeyName, "filename", "format").Order("id desc").Limit(limit).Find(&rows)
	g.Items = make([]searchRef, len(rows))
	for i, sb := range rows {
		g.Items[i] = searchRef{Kind: "sbom", ID: sb.ID, Label: sb.Name, Sub: strings.TrimSpace(sb.Format + searchSep + sb.Filename)}
	}
	return g
}
