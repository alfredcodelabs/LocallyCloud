#!/usr/bin/env bash
# Run from the directory containing all downloaded package artifacts.
set -euo pipefail
# GitHub replaces '~' in asset names; checksums must use the published names.
for package in *.deb *.cdx.json; do
  published_name="${package//\~/.}"
  if [[ "$package" != "$published_name" ]]; then
    mv -- "$package" "$published_name"
  fi
done
python3 - <<'PY'
import hashlib
import json
from pathlib import Path
fragments = [json.loads(Path(f'extenddb-{arch}.json').read_text()) for arch in ('x86_64', 'arm64')]
catalog = {key:value for key,value in fragments[0].items() if key != 'artifacts'}
artifacts = []
for arch, fragment in zip(('x86_64', 'arm64'), fragments):
    assert {key:value for key,value in fragment.items() if key != 'artifacts'} == catalog
    assert len(fragment['artifacts']) == 1
    artifact = fragment['artifacts'][0]
    assert artifact['architecture'] == arch
    for kind, suffix in [('binary', ''), ('notices', '.LICENSES.txt')]:
        item = artifact[kind]
        assert item['name'] == f'locallycloud-extenddb-worker-linux-{arch}{suffix}'
        body = Path(item['name']).read_bytes()
        assert len(body) == item['size'] and hashlib.sha256(body).hexdigest() == item['sha256']
    artifacts.append(artifact)
catalog['artifacts'] = artifacts
Path('components.json').write_text(json.dumps(catalog, indent=2) + '\n')
assert len(list(Path('.').glob('*.deb'))) == 2, 'Expected amd64 and arm64 Debian packages'
assert len(list(Path('.').glob('*.AppImage'))) == 2, 'Expected x86_64 and aarch64 AppImages'
assert len(list(Path('.').glob('*.pkg.tar.zst'))) == 1, 'Expected the Arch x86_64 package'
inventories = [(p.with_suffix('.cdx.json'), 'locallycloud') for p in Path('.').glob('*.deb')]
inventories += [(p.with_suffix('.cdx.json'), 'locallycloud') for p in Path('.').glob('*.AppImage')]
inventories += [(Path(p.name.removesuffix('.pkg.tar.zst') + '.cdx.json'), 'locallycloud') for p in Path('.').glob('*.pkg.tar.zst')]
inventories += [(Path(f'extenddb-{arch}.cdx.json'), 'locallycloud-extenddb-worker') for arch in ('x86_64', 'arm64')]
for path, component in inventories:
    inventory = json.loads(path.read_text())
    assert inventory['bomFormat'] == 'CycloneDX' and inventory['specVersion'] == '1.5'
    assert inventory['metadata']['component']['name'] == component
    assert inventory['components'], f'Empty dependency inventory: {path}'
PY
sha256sum -- *.deb *.pkg.tar.zst *.AppImage *.cdx.json locallycloud-extenddb-worker-linux-* components.json > SHA256SUMS
sha256sum --check SHA256SUMS
