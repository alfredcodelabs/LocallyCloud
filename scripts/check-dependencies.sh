#!/usr/bin/env bash
# Audit both shipped Rust dependency graphs. Extra arguments go to cargo-audit.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v cargo-audit >/dev/null || { echo 'Install cargo-audit 0.23.0 to check dependencies.' >&2; exit 1; }
status=0
for lock in "$ROOT/Cargo.lock" "$ROOT/crates/dynamodb/adapters/extenddb-worker/Cargo.lock"; do
  cargo audit --no-yanked --target-os linux --target-arch x86_64 --target-arch aarch64 --file "$lock" "$@" || status=1
done
exit "$status"
