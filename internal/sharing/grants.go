package sharing

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"

	appconfig "scrutineer/internal/config"
	"scrutineer/internal/db"
)

// GrantSource supplies operator-managed repository grants for an authenticated
// GitHub user. Keeping this seam independent from YAML lets a database-backed
// source replace StaticGrantSource later without changing request authorization.
type GrantSource interface {
	RepositoryIDs(context.Context, int64) (map[uint]struct{}, error)
}

type grantEntry struct {
	RepositoryIDs map[uint]struct{}
	ExpiresAt     *time.Time
}

// StaticGrantSource is an immutable set of validated grants compiled when the
// sharing process starts. Repository URLs have already been resolved to local
// database IDs, so request-time lookup cannot accidentally broaden a grant.
type StaticGrantSource struct {
	byUser map[int64]grantEntry
	now    func() time.Time
	count  int
}

// EmptyGrantSource returns a static source containing no manual grants.
func EmptyGrantSource() *StaticGrantSource {
	return &StaticGrantSource{byUser: map[int64]grantEntry{}, now: time.Now}
}

// CompileStaticGrants validates configured identities and repository URLs,
// resolves every repository to exactly one Scrutineer row, and returns an
// immutable request-time lookup. Any typo fails startup rather than silently
// granting the wrong repository or producing a misleading partial policy.
func CompileStaticGrants(ctx context.Context, gdb *gorm.DB, configured []appconfig.SharingAccessGrant) (*StaticGrantSource, error) {
	source := EmptyGrantSource()
	if len(configured) == 0 {
		return source, nil
	}

	var rows []db.Repository
	if err := gdb.WithContext(ctx).
		Model(&db.Repository{}).
		Select("id", "url", "html_url").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("sharing: load repositories for access grants: %w", err)
	}
	byURL := make(map[string]map[uint]struct{}, len(rows)*2)
	for _, row := range rows {
		for _, raw := range []string{row.URL, row.HTMLURL} {
			key := normURL(raw)
			if !strings.HasPrefix(key, "github.com/") {
				continue
			}
			if byURL[key] == nil {
				byURL[key] = make(map[uint]struct{})
			}
			byURL[key][row.ID] = struct{}{}
		}
	}

	seenUsers := make(map[int64]struct{}, len(configured))
	for i, grant := range configured {
		position := i + 1
		if grant.GitHubUserID <= 0 {
			return nil, fmt.Errorf("sharing: access_grants[%d]: github_user_id must be positive", position)
		}
		if _, duplicate := seenUsers[grant.GitHubUserID]; duplicate {
			return nil, fmt.Errorf("sharing: access_grants[%d]: duplicate github_user_id %d", position, grant.GitHubUserID)
		}
		seenUsers[grant.GitHubUserID] = struct{}{}
		if len(grant.Repositories) == 0 {
			return nil, fmt.Errorf("sharing: access_grants[%d]: repositories must not be empty", position)
		}
		if grant.ExpiresAt != nil && !grant.ExpiresAt.After(source.now()) {
			return nil, fmt.Errorf("sharing: access_grants[%d]: expires_at must be in the future", position)
		}

		entry := grantEntry{RepositoryIDs: make(map[uint]struct{}), ExpiresAt: grant.ExpiresAt}
		seenRepositories := make(map[string]struct{}, len(grant.Repositories))
		for _, raw := range grant.Repositories {
			key, err := canonicalGitHubRepository(raw)
			if err != nil {
				return nil, fmt.Errorf("sharing: access_grants[%d]: %w", position, err)
			}
			if _, duplicate := seenRepositories[key]; duplicate {
				return nil, fmt.Errorf("sharing: access_grants[%d]: duplicate repository %q", position, raw)
			}
			seenRepositories[key] = struct{}{}

			ids := byURL[key]
			switch len(ids) {
			case 0:
				return nil, fmt.Errorf("sharing: access_grants[%d]: repository %q is not in Scrutineer", position, raw)
			case 1:
				for id := range ids {
					entry.RepositoryIDs[id] = struct{}{}
				}
			default:
				resolved := make([]int, 0, len(ids))
				for id := range ids {
					resolved = append(resolved, int(id))
				}
				sort.Ints(resolved)
				return nil, fmt.Errorf("sharing: access_grants[%d]: repository %q matches multiple Scrutineer repository IDs %v", position, raw, resolved)
			}
		}
		source.byUser[grant.GitHubUserID] = entry
		source.count += len(entry.RepositoryIDs)
	}
	return source, nil
}

// RepositoryIDs returns a copy so callers can safely union it into a request
// scope without mutating the startup policy. Expiration is evaluated on every
// request, so a running server never honors a grant past its deadline.
func (s *StaticGrantSource) RepositoryIDs(_ context.Context, githubUserID int64) (map[uint]struct{}, error) {
	out := make(map[uint]struct{})
	if s == nil {
		return out, nil
	}
	entry, ok := s.byUser[githubUserID]
	if !ok || entry.ExpiresAt != nil && !entry.ExpiresAt.After(s.now()) {
		return out, nil
	}
	for id := range entry.RepositoryIDs {
		out[id] = struct{}{}
	}
	return out, nil
}

// UserCount and RepositoryGrantCount are used for a non-sensitive startup
// summary. They do not expose which users or repositories are configured.
func (s *StaticGrantSource) UserCount() int {
	if s == nil {
		return 0
	}
	return len(s.byUser)
}

func (s *StaticGrantSource) RepositoryGrantCount() int {
	if s == nil {
		return 0
	}
	return s.count
}

var (
	githubOwnerPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	githubRepoPattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

func canonicalGitHubRepository(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, "github.com") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("repository %q must be an exact https://github.com/owner/repository URL", raw)
	}
	path := strings.TrimSuffix(strings.Trim(u.EscapedPath(), "/"), ".git")
	parts := strings.Split(path, "/")
	if len(parts) != 2 || !githubOwnerPattern.MatchString(parts[0]) || !githubRepoPattern.MatchString(parts[1]) {
		return "", fmt.Errorf("repository %q must be an exact https://github.com/owner/repository URL", raw)
	}
	return "github.com/" + strings.ToLower(parts[0]) + "/" + strings.ToLower(parts[1]), nil
}
