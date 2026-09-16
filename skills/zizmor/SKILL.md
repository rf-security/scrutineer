---
name: zizmor
description: Audit GitHub Actions workflows with zizmor and explain reported hits using bundled trust-boundary references.
license: MIT
compatibility: Requires `zizmor` (https://github.com/zizmorcore/zizmor) and `python3` on PATH. Reads bundled GitHub Actions security references from `./references`; no external network access is needed.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: findings
  scrutineer.model: mid
---

# zizmor

Run zizmor against `./src/.github/workflows`, then explain each reported issue from the surrounding workflow and its effective trust boundary. The converter decides which findings exist; the reference pack helps make their exploit chain, impact, and remediation precise.

## Workspace

- `./src` — the cloned repository
- `./scripts/scan.py` — the wrapper
- `./references` — GitHub Actions attack-pattern and false-positive guidance
- `./zizmor.json` — intermediate findings emitted by the wrapper
- `./report.json` — write the findings report here
- `./schema.json` — output shape

## Available scripts

- `scripts/scan.py` — invokes `zizmor --no-exit-codes --format json .github/workflows` and converts the output. If the repo has no workflows directory, it writes an empty result so the scan succeeds cleanly. zizmor's severity values are mapped to scrutineer's: `unknown`/`informational`/`low` → `Low`, `medium` → `Medium`, `high` → `High`, `critical` → `Critical`.

## References

Read only the files relevant to each hit:

- `references/expression-injection.md` for untrusted `${{ }}` expressions in shell, script, workflow-command, manual-input, and reusable-workflow contexts.
- `references/privileged-pr-context.md` for `pull_request_target` and other privileged jobs that materialize pull-request content.
- `references/comment-commands.md` for chatops authorization and approval-to-checkout TOCTOU.
- `references/reusable-and-indirect-flows.md` for `workflow_call`, `workflow_run`, local actions, artifacts, and caches crossing trust boundaries.
- `references/permissions-secrets-runners.md` for token scopes, secrets, OIDC, ArtiPACKED, caches, and self-hosted runners.
- `references/supply-chain.md` for mutable third-party action or reusable-workflow references and runtime downloads.
- `references/examples.md` for positive and negative examples that help distinguish an exploitable chain from hardening advice.

The references are review guidance, not evidence that the target is vulnerable. A finding's evidence must come from files under `./src` and the locations emitted by zizmor.

## What to do

```bash
python3 scripts/scan.py > ./zizmor.json
```

The script handles missing workflows directories, a missing zizmor binary, and zizmor's non-zero "I found something" exit code gracefully — don't add retry or error handling on top.

If `zizmor.json` contains an `error` or has no findings, copy it unchanged to `report.json` and stop.

For every finding in `zizmor.json`:

1. Preserve its `id`, `title`, `severity`, `location`, `locations`, and zizmor documentation reference exactly. Do not add, remove, merge, or reclassify findings.
2. Read every cited workflow location plus enough surrounding YAML to identify the trigger, permissions, secrets, checkout ref, action inputs, and commands involved. Follow repository-local reusable workflows, composite actions, and scripts only when the reported path depends on them.
3. Load the relevant reference files listed above. Apply their false-positive controls as well as their attack patterns.
4. Replace `trace` with a concise, source-grounded explanation of the complete chain: attacker-controlled input or mutable dependency, the interpreter or trust-boundary crossing, the privileges or secrets exposed, and the resulting operation. State any unresolved link instead of assuming it.
5. Replace `rating` with a concise justification for the preserved severity, tied to the actual token permissions, secrets, OIDC rights, artifact visibility, runner trust, or write capability present in this repository. If impact depends on configuration outside the repository, say so explicitly.

Do not turn generic hardening advice into a vulnerability. In particular, do not claim exploitation from broad permissions, a mutable action tag, `pull_request_target`, `workflow_run`, a self-hosted runner, or interpolation alone unless the checked-in workflow establishes the corresponding untrusted path and meaningful impact. Do not invent cloud trust policies, repository settings, secret values, or caller behavior that is not visible in `./src`.

Write the enriched object to `./report.json` and validate it against `./schema.json` using the validation endpoint described in the system prompt.
