package sharing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"scrutineer/internal/httpx"
)

// githubAPI is the API base. A var, not a const, so tests can point the client
// at an httptest.Server, mirroring internal/web/org_import.go.
var githubAPI = "https://api.github.com"

const (
	githubUA       = "scrutineer-sharing"
	githubPerPage  = 100
	githubMaxPages = 100
	githubTimeout  = 30 * time.Second
	maxGitHubBody  = 25 * 1024 * 1024
)

// githubUser is the slice of GET /user the portal needs.
type githubUser struct {
	Login string `json:"login"`
}

// githubOrg is the slice of GET /user/orgs the portal needs: the login used to
// list the organization's repositories.
type githubOrg struct {
	Login string `json:"login"`
}

// githubRepo is the slice of GET /user/repos the portal needs: the identifiers
// used to intersect with scrutineer's repositories and the effective
// permission used to decide whether the visitor maintains the repo.
type githubRepo struct {
	FullName    string `json:"full_name"`
	HTMLURL     string `json:"html_url"`
	CloneURL    string `json:"clone_url"`
	Permissions struct {
		Admin    bool `json:"admin"`
		Maintain bool `json:"maintain"`
		Push     bool `json:"push"`
	} `json:"permissions"`
}

// maintained reports whether the visitor's effective permission on the repo is
// enough to be considered a maintainer (admin, maintain, or push/write).
func (r githubRepo) maintained() bool {
	return r.Permissions.Admin || r.Permissions.Maintain || r.Permissions.Push
}

// fetchUser returns the authenticated visitor's GitHub login.
func fetchUser(ctx context.Context, token string) (string, error) {
	var u githubUser
	if err := githubGet(ctx, token, githubAPI+"/user", &u); err != nil {
		return "", err
	}
	if u.Login == "" {
		return "", fmt.Errorf("sharing: GitHub returned an empty login")
	}
	return u.Login, nil
}

// fetchMaintainedRepos returns every repository the visitor maintains, built
// from two sources so it captures write access that comes through an
// organization and not just direct ownership:
//
//  1. Repositories the visitor owns directly (ownership implies full access).
//  2. Repositories in each organization the visitor belongs to on which their
//     effective permission — as reported by the org repository listing for the
//     authenticated user — is write or better.
//
// Scoping the second scan to the visitor's own memberships bounds the GitHub
// requests to their actual affiliation surface rather than every repository
// scrutineer tracks. It reads only public repositories' permissions, so it
// needs no repository OAuth scope beyond the org read already granted.
func fetchMaintainedRepos(ctx context.Context, token string) ([]githubRepo, error) {
	ctx, cancel := context.WithTimeout(ctx, githubTimeout)
	defer cancel()

	// 1. Directly owned repositories.
	maintained, err := githubGetPaged[githubRepo](ctx, token, "/user/repos", url.Values{"affiliation": {"owner"}})
	if err != nil {
		return nil, err
	}

	// 2. Organization repositories the visitor can write to.
	orgs, err := githubGetPaged[githubOrg](ctx, token, "/user/orgs", nil)
	if err != nil {
		return nil, err
	}
	for _, org := range orgs {
		repos, err := githubGetPaged[githubRepo](ctx, token, "/orgs/"+url.PathEscape(org.Login)+"/repos", nil)
		if err != nil {
			return nil, err
		}
		for _, r := range repos {
			if r.maintained() {
				maintained = append(maintained, r)
			}
		}
	}
	return maintained, nil
}

// githubGetPaged fetches every page of a GitHub list endpoint (path is the
// portion after githubAPI, with no query string) and concatenates each page,
// decoded as a slice of T. Pagination stops at the first short page.
func githubGetPaged[T any](ctx context.Context, token, path string, extra url.Values) ([]T, error) {
	var all []T
	for page := 1; page <= githubMaxPages; page++ {
		q := url.Values{
			"per_page": {fmt.Sprint(githubPerPage)},
			"page":     {fmt.Sprint(page)},
		}
		for k, vs := range extra {
			q[k] = vs
		}
		var batch []T
		if err := githubGet(ctx, token, githubAPI+path+"?"+q.Encode(), &batch); err != nil {
			return nil, err
		}
		all = append(all, batch...)
		// A short page is the last page.
		if len(batch) < githubPerPage {
			break
		}
	}
	return all, nil
}

// revokeGrant asks GitHub to delete the OAuth app's authorization grant for the
// visitor, invalidating the access token and any other token issued under the
// same grant. This is what makes "sign out" stick: clearing the local session
// cookie alone leaves the app authorized, so the next login silently re-issues
// a token and bounces the visitor straight back in. Deleting the grant forces a
// fresh authorization prompt instead.
//
// It authenticates with the app's client_id/client_secret over HTTP Basic, as
// GitHub's OAuth-application endpoints require. A 204 is success; a 404 means
// the grant is already gone — both are fine for logout.
func revokeGrant(ctx context.Context, clientID, clientSecret, token string) error {
	ctx, cancel := context.WithTimeout(ctx, githubTimeout)
	defer cancel()

	body, err := json.Marshal(struct {
		AccessToken string `json:"access_token"`
	}{AccessToken: token})
	if err != nil {
		return err
	}
	endpoint := githubAPI + "/applications/" + url.PathEscape(clientID) + "/grant"
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", githubUA)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.SetBasicAuth(clientID, clientSecret)

	// httpx.DoRetry only handles idempotent GETs; a single best-effort DELETE via
	// the default client (bounded by the context timeout above) is enough here.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxGitHubBody))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("sharing: GitHub grant revocation returned %d for %s", resp.StatusCode, endpointPath(endpoint))
	}
	return nil
}

// githubGet issues an authenticated GET and decodes a JSON response into dst.
func githubGet(ctx context.Context, token, endpoint string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", githubUA)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpx.DoRetry(req, httpx.RetryOptions{})
	if err != nil {
		return err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGitHubBody))
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sharing: GitHub API returned %d for %s", resp.StatusCode, endpointPath(endpoint))
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("sharing: decode GitHub response: %w", err)
	}
	return nil
}

// endpointPath strips the query string so error messages don't echo tokens
// (there are none in the query today, but this keeps it safe if that changes).
func endpointPath(endpoint string) string {
	if i := strings.IndexByte(endpoint, '?'); i >= 0 {
		return endpoint[:i]
	}
	return endpoint
}
