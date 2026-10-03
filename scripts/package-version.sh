#!/usr/bin/env bash
# Cargo.toml is the single source of the product version.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# -ge 1 && $# -le 2 ]] || { echo 'Usage: package-version.sh product|tag|arch|debian [debian-revision]' >&2; exit 1; }
VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/{s/^version = "\([^"]*\)"/\1/p;}' "$ROOT/Cargo.toml")"
# Release policy: X.Y.Z or X.Y.Z-{alpha,beta,rc}.N, with N starting at 1.
if [[ ! "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(alpha|beta|rc)\.([1-9][0-9]*))?$ ]]; then
  echo "Invalid product version: $VERSION. Expected X.Y.Z or X.Y.Z-beta.N (also alpha/rc)." >&2
  exit 1
fi
REVISION="${2:-1}"
[[ "$REVISION" =~ ^[1-9][0-9]*$ ]] || { echo "Invalid package revision: $REVISION" >&2; exit 1; }
case "$1" in
  product) printf '%s\n' "$VERSION" ;;
  tag) printf 'v%s\n' "$VERSION" ;;
  arch) printf '%s\n' "${VERSION/-/}" ;;
  debian) printf '%s-%s\n' "${VERSION/-/\~}" "$REVISION" ;;
  *) echo "Unknown version format: $1" >&2; exit 1 ;;
esac
