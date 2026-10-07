#!/usr/bin/env bash
# Point the AUR recipe at a published release tag: update pkgver, _tag and sha256sums from the
# GitHub tag archive, then regenerate .SRCINFO. Run on Arch (needs makepkg) after the tag exists.
# Usage: packaging/aur/update.sh [TAG]   (default: the tag derived from Cargo.toml)
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
TAG="${1:-$(bash "$ROOT/scripts/package-version.sh" tag)}"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[1-9][0-9]*)?$ ]] || {
  echo "Invalid tag: $TAG" >&2
  exit 1
}
PKGVER="$(printf '%s' "${TAG#v}" | tr -d '-')"
URL="https://github.com/alfredcodelabs/LocallyCloud/archive/refs/tags/$TAG.tar.gz"

SHA256="$(curl --fail --show-error --silent --location --proto '=https' "$URL" | sha256sum | cut -d' ' -f1)"
sed -i \
  -e "s/^pkgver=.*/pkgver=$PKGVER/" \
  -e "s/^_tag=.*/_tag=$TAG/" \
  -e "s/^pkgrel=.*/pkgrel=1/" \
  -e "s/^sha256sums=.*/sha256sums=('$SHA256')/" \
  "$DIR/PKGBUILD"
(cd "$DIR" && makepkg --printsrcinfo > .SRCINFO)
echo "PKGBUILD and .SRCINFO now target $TAG ($PKGVER, sha256 $SHA256)"
