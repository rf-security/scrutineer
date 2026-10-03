#!/usr/bin/env bash

set -euo pipefail

tests=0

fail() {
  printf 'not ok %s - %s\n' "$tests" "$1" >&2
  exit 1
}

assert_eq() {
  local expected=$1
  local actual=$2
  local label=$3
  tests=$((tests + 1))
  if [ "$actual" != "$expected" ]; then
    printf 'expected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
    fail "$label"
  fi
  printf 'ok %s - %s\n' "$tests" "$label"
}

# The fixture verifies argument and environment preservation on every attempt.
if [ "${1:-}" = fixture ]; then
  shift
  assert_eq 2 "$#" 'fixture argument count'
  assert_eq 'argument with spaces' "$2" 'fixture argument preservation'
  assert_eq /out "${GOBIN:-}" 'fixture environment preservation'
  count=$(cat "$TEST_DIR/count")
  count=$((count + 1))
  printf '%s\n' "$count" > "$TEST_DIR/count"
  [ "$count" -ge "$1" ] || exit 42
  exit 0
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEST_DIR=$(mktemp -d)
export TEST_DIR
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM
mkdir "$TEST_DIR/bin"
printf '#!/bin/sh\nprintf "%%s\\n" "$1" >> "$TEST_DIR/sleeps"\n' > "$TEST_DIR/bin/sleep"
chmod +x "$TEST_DIR/bin/sleep"
PATH="$TEST_DIR/bin:$PATH"
GOBIN=/out
export PATH GOBIN

check() {
  local name=$1
  local target=$2
  local expected_status=$3
  local expected_count=$4
  local expected_sleeps=$5
  printf '0\n' > "$TEST_DIR/count"
  : > "$TEST_DIR/sleeps"
  local status=0
  sh "$root/scripts/retry-build-command.sh" bash "$root/scripts/retry-build-command_test.sh" fixture "$target" 'argument with spaces' > /dev/null || status=$?
  assert_eq "$expected_status" "$status" "$name: exit status"
  assert_eq "$expected_count" "$(cat "$TEST_DIR/count")" "$name: attempt count"
  assert_eq "$expected_sleeps" "$(cat "$TEST_DIR/sleeps")" "$name: retry delays"
}

check 'immediate success' 1 0 1 ''
check 'second attempt succeeds' 2 0 2 5
check 'third attempt succeeds' 3 0 3 $'5\n10'
check 'retries exhausted' 4 42 3 $'5\n10'
status=0
sh "$root/scripts/retry-build-command.sh" || status=$?
assert_eq 64 "$status" 'missing command: exit status'
printf '1..%s\n' "$tests"
