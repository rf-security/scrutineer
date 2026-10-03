# Package manager threat model

Adapted from Andrew Nesbitt's [Package Manager Threat Model](https://nesbitt.io/package-manager-threat-model.md).
Apply it to the implementation being scanned and cite source evidence for
each conclusion. Historical advisory examples are omitted; similarity to a
past vulnerability does not establish a flaw in this repository.

## Scope and trust boundary

Identify whether the scope contains a client, registry, proxy, or a combination.
Name the public entry points, supported platforms, enabled protections, and
the privileges of each process. Read the applicable client or registry checks
and every shared check in [weakness-patterns.md](weakness-patterns.md), then
the relevant questions in [design-properties.md](design-properties.md).

Establish which actors the project places inside its boundary. Typical trusted
actors include maintainers acting through reviewed changes, the hosting and
identity providers, and the base OS. Typical untrusted actors include package
authors, download servers, third-party repository authors, PR authors, network
attackers, and other registry users. Confirm these roles from the project;
do not silently assign every dependency author the maintainer's authority.

An attacker who already controls the victim's account, shell, environment, or
working directory is normally outside the tool's guarantees. Distinguish that
from a victim opening an untrusted checkout, another OS user planting files in
a shared location, or an unprivileged user supplying data to a privileged
installer. Those cases can cross a boundary without control of the victim's
account. State the actual prerequisite for each candidate.

Executing package code may be intentional. Record when that authority is
granted and what runs before it. Compare executable manifests with declarative
formats, script-disabled modes, and sandbox promises. A valid checksum proves
byte identity; package-author-controlled bytes still require safe parsing and
extraction. Intended behavior with security consequences belongs in design
properties unless an implementation violates a stated or evidenced boundary.

## Evidence and reporting

Trace each candidate as attacker-controlled source -> filters and checks ->
sink. Cite the real CLI, exported API, HTTP route, job, or release workflow
that reaches it. Check sibling backends and alternate paths when one path has
a guard; a check on one downloader does not establish safety for all of them.
Keep deployment behavior, dependency defaults, and platform semantics as open
questions when the available source cannot establish them.

Review weakness patterns and design questions against the same code. Follow
connections between features: a confined build can return an install plan to
a privileged parent, or a token exchange can undo the restriction applied at
issuance. Consolidate evidence that reaches the same root cause instead of
filing one finding per checklist entry.

The report must retain:

- A scope statement naming trusted and untrusted actors, privileges, entry
  points, and exclusions.
- A source-and-sink inventory naming who controls each input, the intervening
  checks, and the reached operation, with source locations.
- Negative results with the invariant that prevents exploitation and the
  code that enforces it. An empty search is insufficient evidence.
- Unverified assumptions naming what was searched and what code, deployment
  setting, or runtime observation would resolve each question.
- Design properties documenting intended behavior and its security effects.

Only proven boundary violations enter `findings`. A dangerous primitive alone
is a review target, and an untraced suspicion remains an unverified assumption.
List omitted or unfinished dimensions explicitly; do not imply the whole model
was reviewed when only part of it was covered.
