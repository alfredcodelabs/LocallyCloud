#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${LOCALLYCLOUD_INSTALL_PREFIX:-${HOME:?}/.local}"
DEST="$PREFIX/bin/locallycloud"
LICENSE_DEST="$PREFIX/share/licenses/locallycloud/LICENSE.md"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
TMP=""

cleanup() {
  if [[ -n "$TMP" ]]; then
    rm -f -- "$TMP"
  fi
}
trap cleanup EXIT

cargo build --manifest-path "$ROOT/Cargo.toml" --release -p locallycloud --locked
mkdir -p -- "$PREFIX/bin"
TMP="$(mktemp "$PREFIX/bin/.locallycloud.XXXXXXXX")"
install -m 0755 -- "$TARGET_DIR/release/locallycloud" "$TMP"
mv -f -- "$TMP" "$DEST"
TMP=""
mkdir -p -- "$(dirname "$LICENSE_DEST")"
install -m 0644 -- "$ROOT/LICENSE.md" "$LICENSE_DEST"
printf 'Installed %s\n' "$DEST"
