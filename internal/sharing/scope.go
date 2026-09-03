package sharing

import (
	"context"
	"strings"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/web"
)

// resolveScope unions the visitor's GitHub-maintained repositories with exact
// operator-configured repository IDs and returns a read-only view scope. Live
// GitHub repositories are matched by host-qualified clone/HTML URL
// (github.com/owner/repo), avoiding cross-forge collisions. Configured IDs were
// resolved and validated once at startup.
func resolveScope(ctx context.Context, gdb *gorm.DB, repos []githubRepo, grantedRepoIDs map[uint]struct{}) (web.ViewScope, error) {
	authorized := make([]githubRepo, 0, len(repos))
	insufficient := make([]githubRepo, 0, len(repos))
	scope := web.ViewScope{
		RepoIDs:  map[uint]struct{}{},
		ReadOnly: true,
	}
	for id := range grantedRepoIDs {
		scope.RepoIDs[id] = struct{}{}
	}
	for _, repo := range repos {
		if repo.maintained() {
			authorized = append(authorized, repo)
			continue
		}
		insufficient = append(insufficient, repo)
	}

	// Keep the GitHub row behind each normalized URL so matched rows can be
	// removed from the informational "not scanned" list. One GitHub repository
	// has both an HTML and clone URL, which normalize to the same key.
	want := make(map[string][]int, len(authorized))
	for i, r := range authorized {
		addIndexedKey(want, r.HTMLURL, i)
		addIndexedKey(want, r.CloneURL, i)
	}
	if len(want) == 0 && len(grantedRepoIDs) == 0 {
		scope.InsufficientRepositories = externalRepositories(insufficient, nil)
		scope.AuthorizedRepoCount = 0
		scope.UnscannedRepositories = externalRepositories(authorized, nil)
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
	matched := make([]bool, len(authorized))
	// Count configured repositories not already represented by a repository
	// that GitHub authorizes normally, so the informational total is a union.
	manualOnly := make(map[uint]struct{}, len(grantedRepoIDs))
	for id := range grantedRepoIDs {
		manualOnly[id] = struct{}{}
	}
	repoIDsByURL := make(map[string]uint, len(rows)*2)
	for _, row := range rows {
		for _, raw := range []string{row.URL, row.HTMLURL} {
			if key := normURL(raw); key != "" {
				repoIDsByURL[key] = row.ID
			}
		}
		indexes := matchingIndexes(want, row.URL, row.HTMLURL)
		if len(indexes) > 0 {
			scope.RepoIDs[row.ID] = struct{}{}
			delete(manualOnly, row.ID)
			for _, i := range indexes {
				matched[i] = true
			}
		}
	}
	scope.AuthorizedRepoCount = len(authorized) + len(manualOnly)
	scope.UnscannedRepositories = externalRepositories(authorized, matched)
	for _, repo := range insufficient {
		if repositoryIsGranted(repo, repoIDsByURL, grantedRepoIDs) {
			continue
		}
		scope.InsufficientRepositories = append(scope.InsufficientRepositories, externalRepository(repo))
	}
	return scope, nil
}

func repositoryIsGranted(repo githubRepo, repoIDsByURL map[string]uint, grantedRepoIDs map[uint]struct{}) bool {
	for _, raw := range []string{repo.HTMLURL, repo.CloneURL} {
		if id := repoIDsByURL[normURL(raw)]; id != 0 {
			if _, granted := grantedRepoIDs[id]; granted {
				return true
			}
		}
	}
	return false
}

func addIndexedKey(set map[string][]int, rawURL string, index int) {
	k := normURL(rawURL)
	if k == "" {
		return
	}
	for _, existing := range set[k] {
		if existing == index {
			return
		}
	}
	set[k] = append(set[k], index)
}

func matchingIndexes(set map[string][]int, rawURLs ...string) []int {
	seen := make(map[int]struct{})
	var indexes []int
	for _, rawURL := range rawURLs {
		for _, index := range set[normURL(rawURL)] {
			if _, ok := seen[index]; ok {
				continue
			}
			seen[index] = struct{}{}
			indexes = append(indexes, index)
		}
	}
	return indexes
}

func externalRepositories(repos []githubRepo, matched []bool) []web.ExternalRepository {
	var out []web.ExternalRepository
	for i, repo := range repos {
		if matched != nil && matched[i] {
			continue
		}
		out = append(out, externalRepository(repo))
	}
	return out
}

func externalRepository(repo githubRepo) web.ExternalRepository {
	return web.ExternalRepository{
		Name:   repo.FullName,
		URL:    repo.HTMLURL,
		Access: permissionLabel(repo.ViewerPermission),
	}
}

func permissionLabel(permission string) string {
	switch permission {
	case "READ":
		return "Read access"
	case "TRIAGE":
		return "Triage access"
	default:
		return "Insufficient permission"
	}
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
