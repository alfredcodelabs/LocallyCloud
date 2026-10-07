#!/usr/bin/env bash
# Generate the third-party license notices for the locallycloud binary.
# Usage: third-party-licenses.sh OUTPUT_FILE   (requires cargo-about 0.8)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="${1:?usage: third-party-licenses.sh OUTPUT_FILE}"
command -v cargo-about >/dev/null || { echo 'cargo-about is required' >&2; exit 1; }

mkdir -p "$(dirname "$OUTPUT")"
cargo about generate --locked --fail \
  --manifest-path "$ROOT/crates/server/Cargo.toml" \
  --config "$ROOT/packaging/licenses/about.toml" \
  --output-file "$OUTPUT" \
  "$ROOT/packaging/licenses/third-party-licenses.hbs"
