package sharing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// githubRepo is the slice of repository identity the portal needs to intersect
// GitHub's answer with scrutineer's repositories.
type githubRepo struct {
	FullName         string
	HTMLURL          string
	CloneURL         string
	ViewerPermission string
}

type githubGraphQLRepo struct {
	FullName         string `json:"nameWithOwner"`
	URL              string `json:"url"`
	ViewerPermission string `json:"viewerPermission"`
}

func (r githubRepo) maintained() bool {
	return canSeeFindings(r.ViewerPermission)
}

func canSeeFindings(permission string) bool {
	switch permission {
	case "ADMIN", "MAINTAIN", "WRITE":
		return true
	default:
		return false
	}
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

const maintainedRepositoriesQuery = `
query MaintainedRepositories($first: Int!, $after: String) {
  viewer {
    repositories(
      first: $first
      after: $after
      visibility: PUBLIC
      affiliations: [OWNER, COLLABORATOR, ORGANIZATION_MEMBER]
      ownerAffiliations: [OWNER, COLLABORATOR, ORGANIZATION_MEMBER]
      orderBy: {field: NAME, direction: ASC}
    ) {
      nodes {
        nameWithOwner
        url
        viewerPermission
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
}`

type githubGraphQLResponse struct {
	Data *struct {
		Viewer *struct {
			Repositories *struct {
				Nodes    []githubGraphQLRepo `json:"nodes"`
				PageInfo *struct {
					HasNextPage bool    `json:"hasNextPage"`
					EndCursor   *string `json:"endCursor"`
				} `json:"pageInfo"`
			} `json:"repositories"`
		} `json:"viewer"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"errors"`
}

// fetchRepositoryAccess returns every public repository GitHub reports for the
// visitor's owner, collaborator, and organization memberships. The caller
// still has to enforce viewerPermission: READ and TRIAGE repositories are
// returned so the portal can explain why their findings remain hidden.
func fetchRepositoryAccess(ctx context.Context, token string) ([]githubRepo, error) {
	ctx, cancel := context.WithTimeout(ctx, githubTimeout)
	defer cancel()

	var (
		repos      []githubRepo
		after      *string
		seenCursor = make(map[string]struct{})
	)
	for page := 1; page <= githubMaxPages; page++ {
		response, err := githubGraphQL(ctx, token, after)
		if err != nil {
			return nil, err
		}
		if len(response.Errors) > 0 {
			e := response.Errors[0]
			if e.Type != "" {
				return nil, fmt.Errorf("sharing: GitHub GraphQL error (%s): %s", e.Type, e.Message)
			}
			return nil, fmt.Errorf("sharing: GitHub GraphQL error: %s", e.Message)
		}
		if response.Data == nil || response.Data.Viewer == nil ||
			response.Data.Viewer.Repositories == nil || response.Data.Viewer.Repositories.PageInfo == nil {
			return nil, fmt.Errorf("sharing: GitHub GraphQL response omitted repository data")
		}

		connection := response.Data.Viewer.Repositories
		for _, r := range connection.Nodes {
			if r.URL == "" {
				return nil, fmt.Errorf("sharing: GitHub GraphQL returned a repository without a URL")
			}
			repos = append(repos, githubRepo{
				FullName:         r.FullName,
				HTMLURL:          r.URL,
				CloneURL:         strings.TrimSuffix(r.URL, "/") + ".git",
				ViewerPermission: r.ViewerPermission,
			})
		}
		if !connection.PageInfo.HasNextPage {
			return repos, nil
		}
		if connection.PageInfo.EndCursor == nil || *connection.PageInfo.EndCursor == "" {
			return nil, fmt.Errorf("sharing: GitHub GraphQL pagination has another page but no end cursor")
		}
		cursor := *connection.PageInfo.EndCursor
		if _, duplicate := seenCursor[cursor]; duplicate {
			return nil, fmt.Errorf("sharing: GitHub GraphQL pagination repeated cursor %q", cursor)
		}
		seenCursor[cursor] = struct{}{}
		after = &cursor
	}
	return nil, fmt.Errorf("sharing: GitHub GraphQL pagination exceeded %d pages", githubMaxPages)
}

func githubGraphQL(ctx context.Context, token string, after *string) (*githubGraphQLResponse, error) {
	payload, err := json.Marshal(struct {
		Query     string `json:"query"`
		Variables struct {
			First int     `json:"first"`
			After *string `json:"after"`
		} `json:"variables"`
	}{
		Query: maintainedRepositoriesQuery,
		Variables: struct {
			First int     `json:"first"`
			After *string `json:"after"`
		}{First: githubPerPage, After: after},
	})
	if err != nil {
		return nil, err
	}

	endpoint := strings.TrimRight(githubAPI, "/") + "/graphql"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", githubUA)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	// GraphQL uses POST for queries, but this operation is read-only and the
	// bytes.Reader gives the request a GetBody function, so transient failures
	// can safely replay the exact payload.
	resp, err := httpx.DoRetryIdempotentPost(req, httpx.RetryOptions{})
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGitHubBody+1))
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(body) > maxGitHubBody {
		return nil, fmt.Errorf("sharing: GitHub GraphQL response exceeded %d bytes", maxGitHubBody)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &githubHTTPError{StatusCode: resp.StatusCode, Endpoint: endpointPath(endpoint)}
	}
	var result githubGraphQLResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("sharing: decode GitHub GraphQL response: %w", err)
	}
	return &result, nil
}

type githubHTTPError struct {
	StatusCode int
	Endpoint   string
}

func (e *githubHTTPError) Error() string {
	return fmt.Sprintf("sharing: GitHub API returned %d for %s", e.StatusCode, e.Endpoint)
}

func isGitHubUnauthorized(err error) bool {
	var httpErr *githubHTTPError
	return errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusUnauthorized
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
		return &githubHTTPError{StatusCode: resp.StatusCode, Endpoint: endpointPath(endpoint)}
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
