#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${LOCALCLOUD_INSTALL_PREFIX:-${HOME:?}/.local}"
DEST="$PREFIX/bin/localcloud"
LICENSE_DEST="$PREFIX/share/licenses/localcloud/LICENSE.md"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
TMP=""

cleanup() {
  if [[ -n "$TMP" ]]; then
    rm -f -- "$TMP"
  fi
}
trap cleanup EXIT

cargo build --manifest-path "$ROOT/Cargo.toml" --release -p localcloud --locked
mkdir -p -- "$PREFIX/bin"
TMP="$(mktemp "$PREFIX/bin/.localcloud.XXXXXXXX")"
install -m 0755 -- "$TARGET_DIR/release/localcloud" "$TMP"
mv -f -- "$TMP" "$DEST"
TMP=""
mkdir -p -- "$(dirname "$LICENSE_DEST")"
install -m 0644 -- "$ROOT/LICENSE.md" "$LICENSE_DEST"
printf 'Installed %s\n' "$DEST"
