#!/usr/bin/env bash
# Validate a proposed tag, or every release tag on this commit, before building.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# -le 1 ]] || { echo 'Usage: check-release-version.sh [vVERSION]' >&2; exit 1; }
expected="$(bash "$ROOT/scripts/package-version.sh" tag)"
check_tag() {
  if [[ "$1" != "$expected" ]]; then
    echo "Tag $1 does not match Cargo.toml ($expected). Update Cargo.toml and Cargo.lock before tagging; do not move published tags." >&2
    exit 1
  fi
}
if [[ $# == 1 ]]; then
  check_tag "$1"
else
  tags="$(git -C "$ROOT" tag --points-at HEAD --list 'v*')"
  while IFS= read -r tag; do
    [[ -z "$tag" ]] || check_tag "$tag"
  done <<< "$tags"
fi
echo "Release version: $expected"
