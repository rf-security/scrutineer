# Build tooling threat model

## Reference and limits

This is original, source-review guidance informed by [SLSA v1.0 requirements](https://slsa.dev/spec/v1.0/requirements) and [SLSA v1.0 threats](https://slsa.dev/spec/v1.0/threats), not a reproduction of the specification or a SLSA conformance assessment. Use the versioned v1.0 links and CWE identifiers as references. Applicability depends on what the tool actually implements. Source review cannot establish CI runner isolation, cache server access control, signing infrastructure or what users configure in production without additional evidence.

## Actors and assets

Distinguish the author of an untrusted checkout or pull request, a malicious dependency or plugin, a writer of a shared or remote cache, a local user on a shared machine and a network attacker on a toolchain download path. Do not grant an attacker the user's explicit consent, a command the user typed or a file the user chose to trust. Protect the developer or CI runner account, credentials in the environment, build outputs and caches and the integrity of produced artifacts.

Inventory each relevant boundary as an entry point, workspace-controlled value, effective guard chain and effect. Include discovery of files in parent directories, defaults pinned by the tool and behavior started implicitly by opening, listing or configuring a workspace. Record a component outside the scoped checkout, such as a remote cache server or CI runner configuration, as unavailable evidence rather than treating it as unguarded.

## Workspace trust and auto-execution

References: [SLSA v1.0 threats](https://slsa.dev/spec/v1.0/threats). CWE-94, CWE-829.

Find code that runs when a workspace is opened, configured, built, tested or linted: build scripts, task definitions, plugins, git hooks, lifecycle scripts and editor or language server activation. Trace the load path from the file the workspace controls to the call that executes or imports it. A trust prompt, allowlist or explicit opt-in flag is an effective guard only if it runs before the code and cannot be satisfied by workspace content, for example a setting stored in the same repository that marks it trusted. Look for bypasses such as trust decisions keyed to a path that a checkout can replace, prompts skipped in non-interactive mode and extensions that execute during activation before any prompt. Running a task the user named on the command line is intended behavior. Executing a plugin or hook merely because it exists in the checkout is a finding when the tool does not ask and does not document it.

## Configuration precedence

References: [SLSA v1.0 threats](https://slsa.dev/spec/v1.0/threats). CWE-427, CWE-73.

Determine the order in which the tool merges built-in defaults, system and user configuration, environment variables, command-line flags and repository configuration. A repository file that overrides a user or global setting, for example to change a registry, a compiler path, a shell or a trust option, is a finding when it crosses a security decision. Check configuration discovery that walks parent directories or the current directory and can pick up an attacker-placed file. Check environment injection: values from workspace files copied into the process environment, search paths that include the workspace and variables such as a loader path or `NODE_OPTIONS` style switches accepted from project config.

## Build cache integrity

References: [SLSA v1.0 requirements](https://slsa.dev/spec/v1.0/requirements), [SLSA v1.0 threats](https://slsa.dev/spec/v1.0/threats). CWE-345, CWE-22, CWE-59.

Check whether the cache key covers every input that changes the output: sources, tool version, configuration, environment and flags. An incomplete key lets a poisoned entry satisfy a legitimate build. For shared or remote caches, look for outputs restored without verifying a digest or signature that the writer cannot forge. Look at extraction of cache entries and artifacts: entry names joined to a destination without normalization, archives that can write outside the target directory and symlinks that redirect a later write. A cache keyed and verified by content digest from a trusted source is a design property. A local cache readable and writable only by the invoking user is usually outside the attacker model unless the tool shares it across users or checkouts.

## Toolchain and plugin resolution

References: [SLSA v1.0 requirements](https://slsa.dev/spec/v1.0/requirements). CWE-829, CWE-494.

Trace how the tool finds compilers, plugins, hooks and helper binaries. Look for resolution through the workspace or a search path that includes it, downloads over unauthenticated channels, resolution by mutable names or tags instead of pinned versions or digests and verification that is optional or skipped on a fallback path. A lockfile or checksum that the same untrusted source can rewrite does not pin anything. Pinned, verified downloads and explicit user-supplied paths are design properties. Package installation itself is covered by `audit-package-manager`; here, cover running what installation placed on disk.

## Secrets and environment exposure

References: [SLSA v1.0 threats](https://slsa.dev/spec/v1.0/threats). CWE-532, CWE-200.

Follow credentials from where the tool reads them to where they can leave: logs and verbose output, cache entries, produced artifacts, crash reports, telemetry and child processes. A task or plugin from the workspace inheriting the full parent environment is a finding when the tool advertises isolation or when the secret is unrelated to the task. Check that redaction is applied to the strings actually printed. Environment forwarded to a child by design, with the user in control of the list, is a design property.

## Hermeticity and sandboxing claims

References: [SLSA v1.0 requirements](https://slsa.dev/spec/v1.0/requirements). CWE-693.

If the tool claims to be hermetic, sandboxed or to restrict network, filesystem or environment access for tasks, read the enforcement code and test each claim against it. Look for a restriction applied to one execution path but not to another, an allowlist built from workspace-controlled data, a sandbox that is disabled by a project setting and paths reaching the host through mounts or symlinks. A tool that makes no such claim is not defective for lacking a sandbox. Whether the operating system mechanism the tool relies on is available on a given runner is an assumption.

## Evidence discipline

Every vulnerability needs a reachable first-party source-to-effect path from workspace-controlled input and a concrete security consequence under stated attacker prerequisites. Record checked enforcement points as negative results, intentional semantics as design properties and anything that needs CI runner, cache server, signing or deployment evidence outside the checkout as an unverified assumption. Static review establishes a source argument, not an executed reproduction or SLSA conformance.
