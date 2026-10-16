---
name: subprojects
description: Enumerate scannable packages inside a repository, including a root package alongside its subprojects. Identifies monorepo packages, workspaces, and discrete modules so the analyst can select a scan target. Runs at repo level; writes back a list that surfaces on the repo overview.
license: MIT
compatibility: Needs network access to the scrutineer API only for logging; the enumeration itself is filesystem-only against ./src.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: subprojects
---

# subprojects

List the discrete scannable units inside a repository so the analyst can scope security scans to a subpath instead of the whole tree. A repository with a single package at the root gets an empty list because the default scan already covers it. A monorepo like apache/airflow or kubernetes/kubernetes gets a row per sub-package.

When subprojects are present, also inspect the root manifests for a package with first-party code outside those subprojects. Emit that package with `path: "."`, its manifest name, and its package kind. For example, a root `composer.json` with PSR-4 autoloading into `Classes/` defines a PHP package even when `packages/*` contains JavaScript workspaces. Emit the root Composer package alongside the JavaScript packages. Its root scan retains the manifest, configuration, and other build inputs; do not emit `Classes/` as an isolated package.

A root used only to coordinate workspaces or shared development tools does not need a row. Check the package's own source and entry points rather than treating every root manifest as another package.

## Workspace

- `./src` — the repository at HEAD. Read-only.
- `./context.json` — has `scrutineer.api_base`, `scrutineer.token`, `scrutineer.repository_id`. Not finding-scoped, not subpath-scoped (this skill *produces* subpaths; it does not consume one).
- `./report.json` — write the enumeration here.
- `./schema.json` — output shape.

## How to identify subprojects

A subproject is a sub-folder that looks like an independently buildable, scannable unit. Heuristics, in descending order of signal strength:

1. **Explicit monorepo declarations.** If the repo has any of these at the root, the file names the workspaces directly. Expand any globs against `./src` and emit one row per matched directory:
   - `pnpm-workspace.yaml` — `packages:` glob list
   - `lerna.json` — `packages:` array
   - `nx.json` / `workspace.json` — NX workspace layout
   - `turbo.json` alongside a root `package.json` with a `workspaces` field
   - `go.work` — `use (...)` list
   - root `Cargo.toml` with `[workspace].members`
   - `pyproject.toml` with `[tool.uv.workspace].members` or Rye/hatch equivalents

2. **Sub-folder package manifests.** Scan sub-folders (depth ≤ 3, skip `node_modules`, `vendor`, `.git`, `dist`, `build`, `target`) for any of the manifests below. Run this even when a workspace declaration exists, then union the two sets — `go.work` and friends are often incomplete.
   - `go.mod` → go-module
   - `package.json` with a `name` field → npm-package
   - `pyproject.toml` / `setup.py` / `setup.cfg` → python-package
   - `Cargo.toml` with `[package]` → rust-crate
   - `composer.json` → composer-package
   - `pom.xml` or `build.gradle[.kts]` → maven/gradle-module
   - `Gemfile` and/or `*.gemspec` → ruby-gem
   - `Package.swift` → swift-package
   - `Dockerfile` alongside a README in a `services/` or `apps/` tree → service

3. **Cluster by top-level directory.** If heuristic 2 produces many hits under a common parent (e.g. `providers/amazon`, `providers/google` each has its own `pyproject.toml`), keep each sub-folder as its own row rather than rolling them up — an analyst may want to scan just one cloud provider's code.

## What NOT to emit

- **An aggregate-only root.** Workspace lists and shared development dependencies alone do not define another package. A single-package repository still gets an empty list because its default scan covers the root.
- **Test fixtures, examples, vendored deps.** Folders called `testdata/`, `fixtures/`, `examples/`, `vendor/`, `third_party/`, `external/` almost always ship code that is not the project itself — skip them.
- **Build outputs.** `dist/`, `build/`, `out/`, `target/`, `node_modules/`, `.venv/`, `__pycache__/` — same.
- **Nested workspaces with no independent manifest.** If a sub-folder has no manifest and is not named by a workspace declaration, it is not a subproject; it is just a sub-folder.

## Output

Write `./report.json`:

```json
{
  "subprojects": [
    {
      "path": "airflow-core",
      "name": "airflow-core",
      "kind": "python-package",
      "description": "Core Airflow scheduler, webserver, and DAG runtime."
    },
    {
      "path": "airflow-ctl",
      "name": "airflow-ctl",
      "kind": "python-package",
      "description": "Airflow CLI distributed as a separate package."
    },
    {
      "path": "providers/amazon",
      "name": "apache-airflow-providers-amazon",
      "kind": "python-package",
      "description": "AWS provider package. Ships operators, hooks, and sensors for S3, EMR, Glue, and other AWS services."
    }
  ]
}
```

Fields:

- `path`: required, relative to repo root, no leading slash. Use `.` for a root package alongside subprojects. Scrutineer converts `.` to the empty repository-wide `Scan.sub_path`; other paths are stored unchanged.
- `name` — short human label. Use the package's own name when the manifest has one (`name` in package.json, `module` path in go.mod, `[package].name` in Cargo.toml); otherwise the last segment of `path`.
- `kind` — the detection hit: `go-module`, `npm-package`, `python-package`, `rust-crate`, `composer-package`, `maven-module`, `gradle-module`, `ruby-gem`, `swift-package`, `service`, etc. Free-form; the UI renders it as a badge.
- `description` — one or two sentences. Read the README in the sub-folder if present, or infer from the package name and directory structure. Keep it specific ("AWS provider package", not "code for AWS").

## Constraints

- Empty list is the correct output for a single-package repo. Do not invent subprojects to avoid an empty array.
- Include a root package only when it has its own source outside the discovered subprojects.
- Do not add more than ~50 rows. If a monorepo is bigger than that, keep the root package and workspace-declared entries first, then fill the remainder by file count (largest first), and set the top-level `notes` field to `"truncated to 50 of N"`.
- Scrutineer replaces the full set on each re-run, so missing rows from a previous run will disappear — do not try to merge with prior output.
