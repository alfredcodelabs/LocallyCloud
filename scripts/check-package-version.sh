#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK_DIR="$(mktemp -d)"
trap 'rm -rf -- "$CHECK_DIR"' EXIT
mkdir -p "$CHECK_DIR/scripts"
cp "$ROOT/scripts/package-version.sh" "$CHECK_DIR/scripts/"
version() { bash "$CHECK_DIR/scripts/package-version.sh" "$@"; }
fixture() { printf '[workspace.package]\nversion = "%s"\n' "$1" > "$CHECK_DIR/Cargo.toml"; }
expect() { [[ "$(version "$1" "${3:-1}")" == "$2" ]] || { echo "Unexpected $1 version" >&2; exit 1; }; }
fixture 0.1.0-beta.1
expect product 0.1.0-beta.1
expect tag v0.1.0-beta.1
expect arch 0.1.0beta.1
expect debian 0.1.0~beta.1-1
expect debian 0.1.0~beta.1-2 2
fixture 0.1.0
expect tag v0.1.0
expect arch 0.1.0
expect debian 0.1.0-1
fixture 0.1.1
expect tag v0.1.1
fixture 1.0.0-rc.2
expect arch 1.0.0rc.2
expect debian 1.0.0~rc.2-1
for invalid in 0.1.0.1 0.1.01.1 0.01.0 0.1.0-beta.01 0.1.0-beta.0 ''; do
  fixture "$invalid"
  if version product >/dev/null 2>&1; then echo "Accepted invalid version: $invalid" >&2; exit 1; fi
done
fixture 0.1.0
for revision in 0 01 bad; do
  if version debian "$revision" >/dev/null 2>&1; then echo "Accepted invalid revision: $revision" >&2; exit 1; fi
done
if version invalid >/dev/null 2>&1; then echo 'Accepted unknown target' >&2; exit 1; fi
if command -v vercmp >/dev/null; then
  [[ "$(vercmp 0.1.0beta.1 0.1.0beta.2)" == -1 ]]
  [[ "$(vercmp 0.1.0beta.2 0.1.0)" == -1 ]]
fi
if command -v dpkg >/dev/null; then
  dpkg --compare-versions '0.1.0~beta.1-1' lt '0.1.0~beta.2-1'
  dpkg --compare-versions '0.1.0~beta.2-1' lt '0.1.0-1'
fi
# The Arch checkout package must derive its version from the real manifest.
startdir="$ROOT/packaging/arch"
source "$startdir/PKGBUILD"
[[ "$pkgver" == "$(bash "$ROOT/scripts/package-version.sh" arch)" ]]
echo 'Version formats, revisions, rejected inputs and Arch alignment: OK'
