#!/usr/bin/env bash
# Shared implementation for scripts/ruby-image-reset.sh and scripts/all-images-reset.sh.
# NOT run directly — each wrapper sets `glob` and `desc`, then sources this file.
#
# Removes locally-built profile images matching $glob (forcing a rebuild on the
# next scan) and pulls the latest upstream runner image they build FROM. Uses
# docker if present, otherwise podman. Profile images are tagged by content
# hash (not :latest), so they are matched by repository glob. Pass -f/--force
# to a wrapper to skip the confirmation prompt.
#
# macOS bash compatibility — this must stay runnable under bash 3.2 (the
# /bin/bash Apple ships) and BSD userland. Do NOT "modernise" it:
#   * No arrays / mapfile: an empty "${arr[@]}" is an "unbound variable" error
#     under `set -u` on bash < 4.4 (incl. macOS 3.2). Image ids are held in a
#     newline string and intentionally word-split while removing them.
#   * No `xargs -r`: -r is a GNU extension that BSD/macOS xargs rejects; the
#     `[ -n "$ids" ]` guard is the portable equivalent.
#   * `pipefail` (bash 3.0+) and `read -rp` (bash 3.2+) are safe.

set -euo pipefail
glob="${glob:?internal error: sourcing wrapper must set glob}"
desc="${desc:?internal error: sourcing wrapper must set desc}"

force=0
for a in "$@"; do
  case "$a" in
    -f|--force) force=1 ;;
    *)
      printf 'unknown argument: %s\nusage: %s [-f|--force]\n' "$a" "$(basename "$0")" >&2
      exit 2
      ;;
  esac
done

rt=podman
command -v docker >/dev/null && rt=docker

report_blocking_children() {
  target_ids=$1
  all_ids=$("$rt" images --no-trunc -aq | sort -u)
  found=0

  for target_id in $target_ids; do
    for candidate_id in $all_ids; do
      [ "$candidate_id" = "$target_id" ] && continue
      parent_id=$("$rt" image inspect --format '{{.Parent}}' "$candidate_id" 2>/dev/null || true)
      if [ "$parent_id" = "$target_id" ]; then
        if [ "$found" -eq 0 ]; then
          printf 'dependent child image(s) outside the selected profile references:\n' >&2
        fi
        if ! "$rt" image inspect \
          --format '  {{.Id}} tags={{json .RepoTags}}' "$candidate_id" >&2; then
          printf '  %s\n' "$candidate_id" >&2
        fi
        found=1
      fi
    done
  done

  if [ "$found" -eq 0 ]; then
    printf 'Docker did not expose the dependent child through image Parent metadata; run `docker image ls -a --no-trunc` to inspect it.\n' >&2
  fi
}

if [ "$force" -ne 1 ]; then
  read -rp "Remove $desc images via $rt and pull the latest runner? [y/N] " ans || true
  case "${ans:-}" in
    [yY] | [yY][eE][sS]) ;;
    *) echo "aborted."; exit 0 ;;
  esac
fi

ids=$("$rt" images --no-trunc -qf reference="$glob" | sort -u)
while [ -n "$ids" ]; do
  removed=0
  # Some profiles build FROM another profile image (ruby-rails FROM ruby).
  # Runtime image listings are not dependency-ordered, and even `rmi -f`
  # refuses to remove a parent while a child exists. Try every target
  # individually, then repeat: removing any leaf makes its parents removable
  # on a later pass.
  for id in $ids; do
    if "$rt" rmi -f "$id" 2>/dev/null; then
      removed=1
    fi
  done

  ids=$("$rt" images --no-trunc -qf reference="$glob" | sort -u)
  if [ -n "$ids" ] && [ "$removed" -eq 0 ]; then
    printf 'unable to remove the remaining %s image(s):\n%s\n' "$desc" "$ids" >&2
    report_blocking_children "$ids"
    # Re-run once without suppressing stderr so the runtime explains the
    # out-of-scope child image or other blocker to the operator.
    for id in $ids; do
      "$rt" rmi -f "$id" || true
    done
    exit 1
  fi
done
"$rt" pull ghcr.io/alpha-omega-security/scrutineer-runner:latest
