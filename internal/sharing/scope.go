package sharing

import (
	"context"
	"strings"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/web"
)

// resolveScope intersects the visitor's GitHub-maintained repositories with the
// repositories scrutineer knows about and returns a read-only view scope over
// the matching IDs. Matching is by host-qualified clone/HTML URL (github.com/
// owner/repo), which both sides always carry, avoiding the cross-forge
// collisions a bare owner/repo key could cause.
func resolveScope(ctx context.Context, gdb *gorm.DB, repos []githubRepo) (web.ViewScope, error) {
	scope := web.ViewScope{RepoIDs: map[uint]struct{}{}, ReadOnly: true}

	want := make(map[string]struct{}, len(repos)*2)
	for _, r := range repos {
		addKey(want, r.HTMLURL)
		addKey(want, r.CloneURL)
	}
	if len(want) == 0 {
		return scope, nil
	}

	// One pass over scrutineer's repositories; keep those whose URL or HTMLURL
	// matches a maintained GitHub repo. The set of scrutineer repos is small
	// (low thousands), so a single scan is cheaper than N per-repo lookups.
	var rows []db.Repository
	if err := gdb.WithContext(ctx).
		Model(&db.Repository{}).
		Select("id", "url", "html_url").
		Find(&rows).Error; err != nil {
		return scope, err
	}
	for _, row := range rows {
		if keyMatches(want, row.URL) || keyMatches(want, row.HTMLURL) {
			scope.RepoIDs[row.ID] = struct{}{}
		}
	}
	return scope, nil
}

func addKey(set map[string]struct{}, rawURL string) {
	if k := normURL(rawURL); k != "" {
		set[k] = struct{}{}
	}
}

func keyMatches(set map[string]struct{}, rawURL string) bool {
	k := normURL(rawURL)
	if k == "" {
		return false
	}
	_, ok := set[k]
	return ok
}

// normURL reduces a repository URL to a comparable host+path key: lower-cased,
// scheme/userinfo/query stripped, and any ".git" suffix or trailing slash
// removed. e.g. "https://github.com/Owner/Repo.git" -> "github.com/owner/repo".
func normURL(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '@'); i >= 0 { // strip any userinfo
		s = s[i+1:]
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")
	return strings.TrimSuffix(s, "/")
}
