# External maintainer sharing portal

The `sharing` command serves a read-only subset of Scrutineer's existing web
UI. Visitors authenticate with GitHub and can see repositories for which
GitHub reports `WRITE`, `MAINTAIN`, or `ADMIN` permission. Every list and detail
request is constrained to the resulting repository IDs; mutating and API
routes are not exposed.

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
always marked `Secure`.

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
must already identify one repository in Scrutineer's database. Wildcards,
organization-wide grants, query strings, and non-GitHub repositories are not
accepted. Duplicate users or repositories, expired grants, malformed URLs,
and missing or ambiguous repositories stop the sharing process at startup.

Configured grants are additive: they do not remove GitHub-derived access and
they never enable writes. The configuration is read once at startup, so adding
or removing a grant requires restarting the sharing process. Removing a grant
then takes effect on the next request after restart; users do not need to sign
out.
