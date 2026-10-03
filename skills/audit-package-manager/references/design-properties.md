# Design properties

Document intended behavior with source or configuration citations. Describe
security consequences separately from findings; these questions establish the
boundary against which the weakness checks are judged. Mark unavailable
deployment evidence and unfinished questions as unverified assumptions.

## Client questions

### Code execution at install time

Which lifecycle hooks run by default, for which direct, transitive, optional,
development, and global dependencies, and as which user? Check the no-scripts
path and its limitations. For sandboxed builds, record supported platforms,
failure behavior, phases outside isolation, and validation of returned output.

### Code execution before installation

Which metadata, audit, lock, dry-run, editor, and shell-integration operations
evaluate code? Compare executable and declarative manifests. Determine whether
project, parent, or build-output configuration can grant network access,
select executables, or load plugins without an approval boundary.

### Lockfile guarantees

Record whether the lock pins identity, origin, content, or only a version, and
which commands enforce it. Compare install and strict CI paths. Determine
whether verification precedes extraction and whether cache reads are checked.
Signed or pinned bytes can still contain hostile archive entries; identity
verification does not replace safe handling of package-author input.

### Resolution across multiple sources

Record precedence, highest-version selection, per-dependency source binding,
failure behavior, and whether added sources affect unrelated dependencies.
Check that the lock's source remains authoritative during installation and
distinguish intentional fallback from a broken source restriction.

## Registry questions

### Namespace allocation

Record name registration, transfer, deletion, re-registration, tombstones,
scopes, and typosquatting controls. For direct VCS resolution, identify which
guarantees instead depend on the forge. Policy absent from the scanned code
remains an open question.

### Maintainer lifecycle

Trace maintainer additions, removals, role changes, organization membership,
package transfers, and publisher configuration. Check visibility to existing
users, publication delays, and durable audit records. Document the authority
granted by account recovery, including recovery through dormant email domains.

### Immutability

Check whether published bytes can change, whether deleted versions can be
reused, and how yanking affects resolution versus locked installs. Compare API,
CDN, and mirror paths and any replacement window following publication.

### Provenance

Determine how an artifact is bound to its claimed repository, commit, and build
workflow. Distinguish publisher-supplied strings, verified attestations, and
trusted-publisher identities. Record whether checks are mandatory and whether
clients enforce them; do not estimate adoption without measured data.

### Publish credentials

Map package scope, allowed actions, expiry, revocation, MFA requirements, and
automation exceptions. Check time and scope enforcement where credentials are
used. Document leak detection or automatic revocation only when supported by
the available code or configuration.

### Feature composition

For ownership, publishing authority, MFA state, membership, and trusted-publisher
bindings, enumerate every creation and exchange path. Check whether one flow's
output can satisfy another flow's precondition with less authority than intended,
including pending publisher setup and flow-specific MFA bypass parameters.

### Blast radius, detection, and abuse

Record publish anomaly signals, malicious-version marking, client refusal,
audit trails, and downstream notification. Review account-age, upload-rate,
and aggregate-resource controls where present. Describe missing detection or
abuse controls as design properties unless a concrete promised limit is bypassed.

## Shared questions

### Package name identity

Compare case, punctuation, Unicode, aliases, and namespace rules at resolution,
publication, authorization, lockfile ingestion, and installation. Include the
target filesystem's equality rules and whether collisions can overwrite another
package or bypass a restriction.

### Mirrors and caching proxies

Identify the authoritative source for internal and mirrored names. Check
propagation of yanks, deletions, and malicious-version flags; checksum and
signature preservation; lockfile origin versus proxy identity; and credentials
on each side of the proxy. Separate repository defaults from unknown deployment
settings.

### The tool's own dependencies

Record vendoring, content pinning, committed locks, and live build resolution
for both the client and service. Trace install hooks in build and deployment
dependencies into processes with publish or registry credentials. Distinguish
an accepted dependency from an input that bypasses the review boundary.

### The tool's own release pipeline

Trace installers, setup actions, bootstrap binaries, CI actions, release jobs,
artifact publication, and self-update into shipped bytes. Check immutable
inputs, branch restrictions, contributor-controlled jobs with secrets, and
verification before replacement. Compare self-update guarantees with package
installation guarantees. For bootstrapped compilers, record the initial binary's
origin and available reproducibility evidence rather than infer it from source.
