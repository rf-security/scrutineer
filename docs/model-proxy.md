# Model API proxy

`-model-proxy` keeps `ANTHROPIC_API_KEY` off scan containers entirely. Without
it, every claude scan container receives the real key as a bare passthrough
environment variable (the docker/podman CLI copies its value from the host
process), so any code a hostile repository runs inside the container can read
it. With `-model-proxy`, the container instead gets a token that is only good
for a small proxy running on the host: the proxy swaps the token for the real
key, forwards the request to Anthropic then revokes the token the moment the
scan ends.

## Scope

This is a narrow, opt-in mitigation for one credential shape:

- **claude backend only.** `-model-proxy` is refused at startup for any other
  `-backend`.
- **API key auth only.** The proxy requires `ANTHROPIC_API_KEY` in the host
  environment. Account login via `CLAUDE_CODE_OAUTH_TOKEN` is out of scope and
  is not read or forwarded; set `ANTHROPIC_API_KEY` instead.
- **Containerised scans only.** `-model-proxy` is refused together with
  `-no-container`, since there is no container to keep the key out of.
  `host_skills` scans always run on the host with the real key regardless of
  this flag: the mitigation only applies to the containerised path.

## Enabling it

    export ANTHROPIC_API_KEY=sk-ant-...
    scrutineer -model-proxy

There is currently no config-file key for it, so pass the flag on the command
line as above even when the rest of the configuration comes from
`scrutineer.yaml`. Startup logs the upstream host once, for example `model
proxy enabled, keeping ANTHROPIC_API_KEY off scan containers
upstream_host=api.anthropic.com`. It never logs the key itself.

If `-model-base-url` (or `ANTHROPIC_BASE_URL`) is set, the proxy forwards to
that host instead of `api.anthropic.com`. That base URL must be reachable from
the scrutineer **host** process, not only from inside scan containers: the
proxy dials it directly.

## Token lifecycle

Each scan calls `RunSkill` once and gets one token, minted from 32 bytes of
`crypto/rand` and valid until the scan's context deadline (or indefinitely if
the scan has none). The container never sees the real key: `ANTHROPIC_BASE_URL`
is rewritten to point at the proxy, reached through the same egress proxy the
scan already uses for every other host. `ANTHROPIC_API_KEY` inside the
container holds the token instead. The token is revoked as soon as `RunSkill`
returns, whether the scan succeeded, failed or was cancelled, so a token never
outlives the scan it was issued for. Revocation is immediate and local (an
in-memory map on the host process): a token cannot be replayed after the scan
ends, including by a process the scan left running.

## Allowed routes

The proxy only forwards a fixed allowlist of Anthropic API routes, matching
what claude-code needs for a scan turn:

- `POST /v1/messages`
- `POST /v1/messages/count_tokens`
- `GET /v1/models`
- `GET /v1/models/{id}`

Anything else, including a nested path under `/v1/models`, an encoded or
unclean path, or an unlisted route entirely, is refused with a 403 in the same
JSON error shape Anthropic's API itself returns, so the CLI surfaces it like
any other API error. A denied request is logged at the host (method and path
only; never the token or the key) and never reaches Anthropic.

## Limits

- The token authenticates to the proxy for the whole scan, so it still permits
  ordinary model use for that duration: a hostile repository's agent turns can
  still spend tokens against the real account while the scan runs, the same as
  today. What `-model-proxy` removes is the ability to exfiltrate the key
  itself and use it outside the scan.
- Model traffic is cleartext between the container and the host. The
  container reaches the proxy over plain `http://`, so the egress proxy (the
  per-scan sidecar on Docker Desktop and rootless podman, scrutineer's own
  process elsewhere) and the model proxy both see prompt and response bodies
  unencrypted. Without `-model-proxy` that traffic is a CONNECT tunnel they
  cannot read. The hop never leaves the host and the per-scan network, and
  the proxy still uses TLS to the upstream API, but anything that can read
  that host traffic can read the conversation.
- The proxy does not add TLS termination or a certificate authority, nor does
  it inspect or rewrite message content. It streams responses (including SSE)
  without buffering. The egress proxy flushes each chunk on the hop from
  the host to the container. On Docker Desktop and rootless podman that hop
  runs in the egress sidecar, which uses the `scrutineer` binary inside the
  runner image: an older runner image still works but delivers a streamed
  turn in larger buffered chunks until the image is updated.
- A base URL with embedded userinfo (`https://user:pass@host/...`) is refused
  at startup: credentials belong in `ANTHROPIC_API_KEY`, not in the URL.
- `host_skills` skills run directly on the host and already have the real
  key in their environment; `-model-proxy` has no effect on them.

See [threatmodel.md](../threatmodel.md) (T13) for how this fits into the
broader egress model. The implementation lives in
`internal/worker/model_proxy.go`.
