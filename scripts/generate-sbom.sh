#!/usr/bin/env bash
# Generate the shipped binary's Rust dependency inventory without compiling it.
set -euo pipefail
[[ $# == 2 ]] || { echo 'Usage: generate-sbom.sh MANIFEST OUTPUT.cdx.json' >&2; exit 1; }
MANIFEST="$(realpath "$1")"
OUTPUT="$(realpath -m "$2")"
command -v cargo-cyclonedx >/dev/null || { echo 'Install cargo-cyclonedx 0.5.10 to generate the SBOM.' >&2; exit 1; }
WORK="$(mktemp -d)"
cleanup() {
  if [[ -f "$WORK/generated" ]]; then
    while IFS= read -r path; do rm -f -- "$path"; done < "$WORK/generated"
  fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT
cargo metadata --locked --manifest-path "$MANIFEST" --format-version 1 > "$WORK/metadata.json"
# The upstream tool emits all workspace binaries; keep only the requested package's inventory.
GENERATED="$(python3 - "$WORK/metadata.json" "$MANIFEST" "$WORK/generated" <<'PYTHON'
import json, pathlib, sys
meta = json.loads(pathlib.Path(sys.argv[1]).read_text())
outputs, selected = [], []
for package in meta['packages']:
    if package['id'] not in meta['workspace_members']:
        continue
    for target in package['targets']:
        if not ({'bin', 'cdylib'} & set(target['kind'])):
            continue
        manifest = pathlib.Path(package['manifest_path'])
        output = manifest.parent / (target['name'] + '_' + '-'.join(target['kind']) + '.cdx.json')
        if output.exists():
            sys.exit('An SBOM already exists beside a manifest; move it before generating another.')
        outputs.append(str(output))
        if manifest == pathlib.Path(sys.argv[2]):
            selected.append(str(output))
if len(selected) != 1:
    sys.exit('The selected package must contain exactly one shipped binary.')
pathlib.Path(sys.argv[3]).write_text(''.join(path + '\n' for path in outputs))
print(selected[0])
PYTHON
)"
cargo cyclonedx --manifest-path "$MANIFEST" --describe binaries --format json --spec-version 1.5
install -Dm644 "$GENERATED" "$OUTPUT"
