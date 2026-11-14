#!/usr/bin/env bash
# Build one native, optional ExtendDB component and its release catalog fragment.
set -euo pipefail
umask 077
[[ $# -ge 2 && $# -le 3 ]] || { echo 'Usage: build-worker.sh NEW_OUTPUT_DIR WORK_DIR [PINNED_SOURCE_ARCHIVE]' >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT="$(realpath -m "$1")"
WORK="$(realpath -m "$2")"
case "$(uname -m)" in
  x86_64) ARCH=x86_64 ;;
  aarch64) ARCH=arm64 ;;
  *) echo 'ExtendDB components require Linux x86_64 or arm64' >&2; exit 1 ;;
esac
[[ "$(uname -s)" == Linux ]] || { echo 'Linux is required' >&2; exit 1; }
command -v cargo-about >/dev/null || { echo 'cargo-about 0.8 is required' >&2; exit 1; }
command -v cargo-cyclonedx >/dev/null || { echo 'cargo-cyclonedx 0.5.10 is required' >&2; exit 1; }
mkdir -p "$WORK"
SOURCE_ARGS=(--directory "$WORK/source")
if [[ $# == 3 ]]; then SOURCE_ARGS+=(--archive "$(realpath "$3")"); fi
PATCH_CONFIG="$(python3 "$ROOT/scripts/prepare-extenddb-worker.py" "${SOURCE_ARGS[@]}")"
CONTEXT="$(mktemp -d "$WORK/cargo-context.XXXXXXXX")"
trap 'rm -rf -- "$CONTEXT"' EXIT
mkdir "$CONTEXT/.cargo"
cp "$PATCH_CONFIG" "$CONTEXT/.cargo/config.toml"
CARGO_TARGET_DIR="$(realpath -m "${CARGO_TARGET_DIR:-$WORK/build}")"
export CARGO_TARGET_DIR
WORKER="$ROOT/crates/dynamodb/adapters/extenddb-worker"
cp "$WORKER/Cargo.toml" "$WORKER/Cargo.lock" "$CONTEXT/"
cp -R "$WORKER/src" "$CONTEXT/src"
MANIFEST="$CONTEXT/Cargo.toml"
cd "$CONTEXT"
cargo build --manifest-path "$MANIFEST" --release --locked -j "${CARGO_BUILD_JOBS:-2}"
BINARY="$CARGO_TARGET_DIR/release/locallycloud-extenddb-worker"
GLIBC_BASELINE="${LOCALLYCLOUD_GLIBC_BASELINE:-2.39}"
GLIBC_REQUIRED="$(objdump -T "$BINARY" | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sed 's/GLIBC_//' | sort -V | tail -1)"
if [[ -z "$GLIBC_REQUIRED" || "$(printf '%s\n%s\n' "$GLIBC_REQUIRED" "$GLIBC_BASELINE" | sort -V | tail -1)" != "$GLIBC_BASELINE" ]]; then
  echo "ExtendDB requires glibc $GLIBC_REQUIRED, above the supported baseline $GLIBC_BASELINE" >&2
  exit 1
fi
# SQLCipher and OpenSSL must be bundled, not additional host requirements.
if readelf -d "$BINARY" | grep -Eq 'Shared library:.*(libsqlite3|libsqlcipher|libssl\.|libcrypto\.)'; then
  echo 'ExtendDB still depends on a shared SQLite, SQLCipher or OpenSSL library' >&2
  exit 1
fi
cargo metadata --manifest-path "$MANIFEST" --locked --format-version 1 > "$WORK/metadata.json"
cargo about generate --locked --fail --manifest-path "$MANIFEST" \
  --config "$ROOT/packaging/licenses/about.toml" \
  --output-file "$WORK/notices.txt" "$ROOT/packaging/licenses/third-party-licenses.hbs"
mkdir "$OUTPUT"
NAME="locallycloud-extenddb-worker-linux-$ARCH"
install -m755 "$BINARY" "$OUTPUT/$NAME"
install -m644 "$WORK/notices.txt" "$OUTPUT/$NAME.LICENSES.txt"
VERSION="$(bash "$ROOT/scripts/package-version.sh" tag)"
python3 - "$ROOT" "$WORK" "$OUTPUT" "$ARCH" "$VERSION" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
root, work, output = map(Path, sys.argv[1:4])
arch, version = sys.argv[4:6]
name = f'locallycloud-extenddb-worker-linux-{arch}'
metadata = json.loads((work / 'metadata.json').read_text())
packages = metadata['packages']

def dependency_license(package, relative):
    matches = [p for p in packages if p['name'] == package]
    if len(matches) != 1:
        raise ValueError(f'Expected one {package} dependency')
    return Path(matches[0]['manifest_path']).parent / relative

licenses = [
    root / 'LICENSE.md', work / 'source/source/LICENSE', work / 'source/source/NOTICE',
    dependency_license('libsqlite3-sys', 'sqlcipher/LICENSE'),
    dependency_license('openssl-src', 'openssl/LICENSE.txt'),
]
with (output / f'{name}.LICENSES.txt').open('a') as destination:
    for path in licenses:
        destination.write(f'\n\n--- {path.name} ---\n')
        destination.write(path.read_text())

def artifact(path):
    body = path.read_bytes()
    return {'name':path.name, 'sha256':hashlib.sha256(body).hexdigest(), 'size':len(body)}

catalog = {
    'schema':1, 'component':'extenddb', 'protocol':1, 'version':version,
    'capabilities':['stream-cursors-v1', 'mrec-outbox-v1', 'backups-v1', 'migration-ttl-v1', 'migration-history-v1', 'pitr-history-v1', 'pitr-global-v1', 'table-file-v1'],
    'upstream': json.loads((work / 'source/prepared.json').read_text()),
    'artifacts':[{'architecture':arch, 'binary':artifact(output / name),
                  'notices':artifact(output / f'{name}.LICENSES.txt')}],
}
assert catalog['artifacts'][0]['binary']['size'] <= 128 * 1024 * 1024
assert catalog['artifacts'][0]['notices']['size'] <= 2 * 1024 * 1024
(output / f'extenddb-{arch}.json').write_text(json.dumps(catalog, indent=2) + '\n')
PY

bash "$ROOT/scripts/generate-sbom.sh" "$MANIFEST" "$OUTPUT/extenddb-$ARCH.cdx.json"
