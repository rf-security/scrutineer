# External maintainer sharing portal

The `sharing` command serves a read-only view of Scrutineer to external
maintainers. Visitors authenticate with GitHub and can see repositories for
which GitHub reports `WRITE`, `MAINTAIN`, or `ADMIN` permission. Every list and
detail request is constrained to the resulting repository IDs; mutating routes
are not exposed.

Start the portal against the same configuration and data directory as the main
Scrutineer process:

```sh
export SCRUTINEER_SHARING_GITHUB_CLIENT_ID=...
export SCRUTINEER_SHARING_GITHUB_CLIENT_SECRET=...
export SCRUTINEER_SHARING_SESSION_KEY=...
go run ./cmd/sharing -config ./scrutineer.yaml \
  -base-url https://share.example.org -addr 127.0.0.1:8081
```

Configure the GitHub OAuth App's callback URL as
`https://share.example.org/auth/callback`. Put the portal behind a TLS reverse
proxy when it is exposed publicly; its session and OAuth-state cookies are
always marked `Secure` (except with the loopback-only dev identity below).

## Front end: `-ui=spa` (default) and `-ui=legacy`

With `-ui=spa` the portal serves the portal SPA (`scrutineer-portal-ui`) at
`/`, embedded from `internal/sharing/ui/dist`. The SPA reads a GET-only,
default-deny allow-list of the v2 JSON API (`/api/v1/ui/*`, listed in
`internal/sharing/routes.go`) plus the report/CSAF/OSV/bundle/patch
downloads; every `{id}` is checked against the visitor's scope before the
request is forwarded, and anything else answers 404. The client-facing
contract, including the portal's own `/auth/*` endpoints, is
`openapi.portal.yaml` at the repository root.

`-ui=legacy` keeps the server-rendered HTML portal (`templates/sharing/`) for
one release; it will then be removed.

Embedding a portal build:

```sh
# in ../scrutineer-portal-ui
UI_OUT_DIR=../scrutineer-ui-v2-api/internal/sharing/ui/dist npm run build
# then commit internal/sharing/ui/dist:
#   "Embed portal UI build (scrutineer-portal-ui <sha>)"
```

`SCRUTINEER_SHARING_UI_DIR=<build dir>` serves a build from disk instead of the
embed (re-read per request, so a rebuild needs no restart). The committed
placeholder `index.html` only says the UI is not built.

Session and API behaviour the SPA relies on:

- `GET /auth/session` never blocks or starts a GitHub lookup: 200
  `{authenticated, login, github_user_id, expires_at, access:{state,found,partial}, version}`
  or 401.
- `GET /auth/access` returns the visitor's scope (`authorized_repo_count`,
  `scanned_repo_count`, `repository_ids`, `unscanned`, `insufficient`,
  `incomplete`).
- `GET /auth/login?next=/path` lands on `next` after sign-in (same-origin paths
  only). `POST /auth/logout` with `Accept: application/json` answers 204.
- API failures use the same JSON envelope as the operator UI
  (`{"code","error","request_id"}`): 401 `unauthorized` without a session
  (never a redirect), 503 `unavailable` while GitHub is down (the session is
  kept). Responses carry `Cache-Control: no-store`, `Vary: Cookie` and
  `X-Portal-Scope: complete|partial`.
- Every non-GET/HEAD request needs `Sec-Fetch-Site: same-origin`.
- There is no SSE in the portal; scan logs come from the stored log only.

Regenerate `openapi.portal.yaml` after changing the allow-list,
`internal/sharing/openapi_auth.yaml` or `openapi.yaml`:

```sh
go test ./internal/sharing -run TestPortalOpenAPIGolden -update
```

## Local development: the dev identity

`-dev-login` replaces GitHub with a fake identity, so the portal runs without
OAuth secrets. It refuses to start unless `-addr` (and `-base-url`, which
defaults to `http://<addr>`) is loopback, accepts any loopback `Host` (so a
Vite proxy on `localhost:5173` works), and drops `Secure` from its cookies so
they work over plain http.

```sh
go run ./cmd/sharing -config ./scrutineer.yaml -addr 127.0.0.1:8081 \
  -dev-login octocat -dev-user-id 1 \
  -dev-repos acme/widget,acme/other=READ,acme/unscanned \
  -dev-repo-ids 3,4 -dev-access-delay 0s
```

- `-dev-repos`: GitHub `owner/name` the fake lookup reports, each optionally
  `=ADMIN|MAINTAIN|WRITE|TRIAGE|READ` (default `ADMIN`). They match Scrutineer
  repositories whose URL is `https://github.com/owner/name`; others appear as
  unscanned, and `TRIAGE`/`READ` ones as insufficient.
- `-dev-repo-ids`: Scrutineer repository IDs granted directly.
- `-dev-access-delay`: make the lookup take this long (half the repositories
  arrive halfway), to exercise the progress screen and the partial banner.

`GET /auth/login` signs in immediately and redirects to `next`.

## Explicit repository grants

An operator can add read-only access for a GitHub user who does not have the
usual repository permission:

```yaml
sharing:
  access_grants:
    - github_user_id: 583231
      repositories:
        - https://github.com/acme/widget
        - https://github.com/acme/another-repository
      reason: External security reviewer
      expires_at: 2026-12-31T00:00:00Z
```

`github_user_id` is GitHub's immutable numeric user ID, not the user's login.
An authenticated user can inspect their ID with `gh api user --jq .id`.
`reason` and `expires_at` are optional. Expiration is enforced while the server
is running.

Repository entries must be exact HTTPS `github.com/owner/repository` URLs and
must already identify one repository in Scrutineer's database. They are matched
only against the repository's primary `url`; metadata-derived `html_url` values
are ignored for authorization. Wildcards, organization-wide grants, query
strings, and non-GitHub repositories are not accepted. Duplicate users or
repositories, expired grants, malformed URLs, and missing or ambiguous primary
URLs stop the sharing process at startup.

Configured grants are additive: they do not remove GitHub-derived access and
they never enable writes. The configuration is read once at startup, so adding
or removing a grant requires restarting the sharing process. Removing a grant
then takes effect on the next request after restart; users do not need to sign
out.
