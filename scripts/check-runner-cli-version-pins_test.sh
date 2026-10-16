#!/usr/bin/env bash

set -euo pipefail

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
mkdir -p "$test_dir/scripts" "$test_dir/internal/worker" "$test_dir/.github/workflows"
cp "$root/scripts/check-runner-cli-version-pins.sh" "$test_dir/scripts/"
cp "$root/Dockerfile" "$test_dir/"
cp "$root/.github/workflows/tests.yml" "$test_dir/.github/workflows/"

reset_pins() {
  cp "$root/Dockerfile.runner" "$test_dir/"
  cp "$root/internal/worker/harness.go" "$test_dir/internal/worker/"
}

expect_failure() {
  local label=$1
  shift
  local status=0
  bash "$test_dir/scripts/check-runner-cli-version-pins.sh" > "$test_dir/output" 2>&1 || status=$?
  if [ "$status" -ne 1 ]; then
    printf '%s: expected exit 1, got %s\n' "$label" "$status" >&2
    cat "$test_dir/output" >&2
    exit 1
  fi
  local expected
  for expected in "$@"; do
    if ! grep -Fqx -- "$expected" "$test_dir/output"; then
      printf '%s: missing diagnostic: %s\n' "$label" "$expected" >&2
      cat "$test_dir/output" >&2
      exit 1
    fi
  done
  printf 'ok - %s\n' "$label"
}

reset_pins
bash "$test_dir/scripts/check-runner-cli-version-pins.sh"
printf 'ok - matching pins\n'

sed 's/^ARG CODEX_ARM64_LOCK=rust-v[0-9.]*@/ARG CODEX_ARM64_LOCK=rust-v0.0.0@/' \
  "$root/Dockerfile.runner" > "$test_dir/Dockerfile.runner"
expect_failure 'architecture mismatch' \
  'Codex version pins disagree:' \
  '  arm64: rust-v0.0.0'

reset_pins
sed 's/^const CodexModelCatalogRelease = .*/const CodexModelCatalogRelease = "rust-v0.0.0"/' \
  "$root/internal/worker/harness.go" > "$test_dir/internal/worker/harness.go"
runner_version=$(sed -E -n \
  's/^ARG CODEX_AMD64_LOCK=(rust-v[0-9]+\.[0-9]+\.[0-9]+)@.*/\1/p' "$root/Dockerfile.runner")
expect_failure 'catalog mismatch' \
  'Codex runner and model catalog version pins disagree:' \
  "  runner: $runner_version" \
  '  model catalog: rust-v0.0.0'

reset_pins
sed '/^const CodexModelCatalogRelease = /d' \
  "$root/internal/worker/harness.go" > "$test_dir/internal/worker/harness.go"
expect_failure 'missing catalog pin' \
  'expected exactly one version in Scrutineer Codex model catalog, found 0'
