# Weakness patterns

Apply client checks to installers, resolvers, and their libraries; apply
registry checks to publishing services and package proxies where the behavior
exists. Shared checks apply to either side. For every applicable pattern,
record a finding, an evidenced negative result, or an unresolved assumption.

## Client checks

### Path traversal

Trace archive members, package names, versions, executable names, entry points,
lockfile aliases, patch targets, response filenames, and cache keys into file
operations. Check absolute paths, parent traversal, platform separators,
symlink chains created by earlier archive entries, and hardlink targets.
Verify containment at path-component boundaries and at the operation itself;
a string prefix or a path join alone does not prove containment.

### Argument injection

Inspect each VCS backend, compiler, linker, and downloader invocation for
attacker-controlled options, refs, URLs, and flags. An argv array avoids shell
parsing but still permits option injection. Check the subprocess's actual
option grammar, including placement and support for `--` or
`--end-of-options`; a trailing marker does not protect earlier operands.
In-process VCS implementations need their own checkout protections for metadata
directories, case folding, platform path aliases, and submodule symlinks.

### Integrity checks that fail open

Follow absent, malformed, wrong-content, and failed-verification cases through
every acquisition path. Check TLS certificates, SSH host keys, downgrade
redirects, signatures, and transparency-log proofs where promised. Confirm
verification failure prevents use of the artifact and cannot become a warning
followed by installation through a fallback backend.

### Credential leakage

Trace credentials through redirects, mirrors, dependency hosts, and
server-supplied `Location`, `Link`, or authentication-realm URLs. Check origin
binding at every hop. Inspect logs, error strings, argv, debug output, and
published archives for tokens, URL passwords, private keys, and workspace
secrets. Check publish-file selection for workspaces as well as root packages.

### Dependency confusion

Follow source selection for direct and transitive dependencies, including
source failure, fallback, aliases, and name matching. Check whether a source
added for one dependency can satisfy unrelated names, whether a private name
can resolve publicly, and whether the lockfile's selected origin is enforced.
Distinguish a bypass of source pinning from documented multi-source resolution.

### Local files treated as configuration

Trace project, parent-directory, ignored, and build-output configuration into
plugin loading, credential helpers, shell selection, templates, toolchain
binaries, and executable search paths. Check whether commands advertised as
metadata-only load or execute them before command parsing or user approval.
Include editor integration and directory-change hooks when present.

### Shared filesystem locations

Check temporary, cache, and installation paths for predictable names,
permissions at creation, archive-supplied modes, and symlink or hardlink races.
Follow privileged installers reading unprivileged output and check whether
the object validated is the object later modified. Establish which other
principal can plant or replace the file; same-account control alone is not
evidence of a new boundary violation.

### Terminal escape sequences

Follow package metadata, subprocess stderr, and remote error bodies into
terminal output. Check control-character handling and whether output can
conceal installed content or forge security-relevant messages. Examine HTML
build reports separately for escaping and rate the demonstrated consequence.

### Lockfile bypass

Enumerate every path that puts package bytes on disk, including VCS, optional,
dynamic, cached, and platform-specific dependencies. Check frozen installs,
manifest disagreement, content digests, source URLs, and re-verification on
cache reads. Compare hash, scanner, and extraction interpretations of archives,
including duplicate entries and files accepted as multiple archive formats.

### Protection mechanism bypass

For each sandbox, hook allowlist, source allowlist, anti-downgrade check, or
release-age gate, trace every operation it should constrain. Include fetchers,
alternate update types, inherited file descriptors, platform-specific privilege
dropping, and behavior when isolation is unavailable. Validate install plans,
step lists, and cache records returned by confined code before an unconfined
or privileged parent acts on them.

### Unauthenticated build daemon

Trace build instructions received over local TCP or sockets. Check binding,
socket permissions, peer identity, cookies, or per-session authentication;
loopback alone does not distinguish local principals. State whether an
attacker must share the account, merely share the host, or reach the network.

### Memory corruption

Review native archive and metadata parsers for length-field overflow,
allocation bounds, short reads, off-by-one handling, and format strings in
error paths. Include native dependencies reached from memory-safe code and
identify the first-party entry point into each candidate parser.

## Registry checks

### Publishing to another principal's package

Trace publish, yank, overwrite, ownership-transfer, and administrative routes
to the exact package and variant authorized. Check normalized names, upload
ordering, CDN object keys, orphaned ownership, role changes, and side effects
of nominally read-only requests. Compare the authorized identity with the
stored artifact's identity.

### Account takeover

Inspect login, account recovery, email changes, OAuth redirects, session
validation, MFA transitions, and proxy-header handling. Check whether
mail-scanner requests can complete a login or recovery flow. Record recovery
through a lapsed email domain as a design risk unless a concrete implementation
flaw crosses an additional authentication boundary.

### Stored XSS

Follow package READMEs, descriptions, URLs, and profile fields into rendering.
Inspect HTML sanitization, URL schemes, attributes, CSS, and the effective CSP
where available. Establish whether the payload reaches a maintainer session
and what authority it can exercise; a missing header alone is insufficient.

### Server-side code execution

Trace uploads, imported repositories, manifests, and account input through
deserializers, VCS commands, templates, and shell calls. Revisit client-side
parsers reused by the service. State the service's privileges and attacker
access rather than copying the client-side impact estimate.

### SSRF

Inspect repository imports, webhooks, avatars, remote mirrors, and XML external
entities. Trace redirects and DNS resolution through destination checks for
loopback, private networks, and deployment-specific protected services.
Apply the same reasoning to client features running on CI networks; do not
infer access to an internal service without evidence.

### IDOR

Review object-level authorization for projects, packages, blobs, webhooks,
robot accounts, and cross-repository mounts. Include read-only and batch paths.
An action-level permission must also cover the specific selected object and
tenant, including objects loaded again after an earlier check.

### Token scope

Compare issuance, authentication, token exchange, and endpoint enforcement.
Check that read-only, upload-only, package-limited, or automation credentials
cannot become session-equivalent or gain another organization's authority.
Trace expiry and revocation checks to use, not just database fields.

### Shared-cache leakage

Trace personalized responses through middleware, compression, reverse proxies,
and CDN configuration available in the repository. Inspect cache keys,
authorization variation, and cache-control preservation. If deployment behavior
is unavailable, record that assumption rather than assert another user receives
the response.

## Shared checks

### Unsafe deserialization

Trace package metadata and selectors into object-capable YAML or marshalling
loaders, evaluators, and XML parsers. Establish effective settings for object
construction and external entities. Check both client and server callers of
shared parsers, especially those reached before installation consent.

### Resource exhaustion

Check expanded archive size, file counts, recursive metadata, regex complexity,
negative or overflowing lengths, total-transfer timeouts, and allocations.
Compare per-file limits with aggregate limits and alternate upload paths.
Rate impact against the affected client, shared CI worker, or registry service.

### Weak cryptographic parameters

Determine what each hash, random value, and key-derivation parameter protects.
Check truncated or non-cryptographic integrity hashes, predictable secret
tokens, and ineffective password derivation. Establish the effective algorithm
and parameters from code and pinned dependencies; an algorithm name alone does
not establish exploitability.

### Manifest confusion

Compare submitted metadata, archive metadata, displayed package identity,
dependency analysis, and the installer's interpretation. Check that requested
name and version match the artifact actually accepted. Review cache behavior
after upstream deletion or correction, and distinguish immutable historical
content from a violated removal or identity guarantee.
