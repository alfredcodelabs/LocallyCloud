#!/usr/bin/env python3
"""Prepare checksum-pinned official ExtendDB sources and the local transaction hook."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

COMMIT = 'b5bffa3803758c6028bb40ecdf2bfcae4a051a88'
ARCHIVE_SHA256 = '4499df0036fef0e52b69ed5bb8d2680d478121869459653c9d4431297f7293c4'
ARCHIVE_URL = f'https://codeload.github.com/ExtendDB/extenddb/tar.gz/{COMMIT}'
PACKAGES = ('auth', 'cache', 'core', 'engine', 'storage', 'storage-sqlite')
ROOT = Path(__file__).resolve().parent.parent
PATCH = ROOT / 'crates/dynamodb/adapters/extenddb-worker/patches/0001-sqlite-transaction-mutation-hook.patch'
PATCHES = (PATCH, PATCH.with_name('0002-sqlite-durable-backups.patch'),
           PATCH.with_name('0003-sqlite-migration-ttl-suspension.patch'))
MAX_COMPRESSED = 32 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def tree_digest(path):
    h = hashlib.sha256()
    for file in sorted(path.rglob('*')):
        if file.is_symlink():
            raise ValueError('prepared source contains a symbolic link')
        if file.is_file():
            h.update(str(file.relative_to(path)).encode() + b'\0')
            h.update(bytes.fromhex(digest(file)))
    return h.hexdigest()


def unpack(archive, destination):
    """Never follow archive links; documentation symlinks are not build inputs."""
    total = 0
    prefix = f'extenddb-{COMMIT}'
    with tarfile.open(archive, 'r:gz') as source:
        for count, member in enumerate(source, 1):
            if count > 4096:
                raise ValueError('source archive has too many entries')
            path = PurePosixPath(member.name)
            if (path.is_absolute() or not path.parts or path.parts[0] != prefix
                    or '..' in path.parts or '\\' in member.name
                    or '\0' in member.name or len(member.name) > 4096):
                raise ValueError('unsafe source archive path')
            if member.size<0 or member.size>16*1024*1024:
                raise ValueError('source archive member exceeds size limit')
            total += member.size
            if total>MAX_EXPANDED:
                raise ValueError('expanded source archive exceeds limit')
            if member.issym() or member.islnk():
                continue
            relative = Path(*path.parts[1:])
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            if not member.isfile() or member.size > 16 * 1024 * 1024:
                raise ValueError('unsupported source archive entry')
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError('missing source archive body')
            with stream, target.open('xb') as output:
                remaining = member.size
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError('truncated source archive')
                    output.write(chunk)
                    remaining -= len(chunk)


def prepare(directory, supplied_archive=None):
    if directory.is_symlink():
        raise ValueError('preparation directory must not be a symlink')
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink() or directory.stat().st_mode & 0o077:
        raise ValueError('preparation directory must be private (0700)')
    source = directory / 'source'
    marker = directory / 'prepared.json'
    expected = {'commit': COMMIT, 'archive_sha256': ARCHIVE_SHA256,
                'patch_sha256': digest(PATCH),
                'patches': [{'name': patch.name, 'sha256': digest(patch)} for patch in PATCHES]}
    if source.is_symlink() or marker.is_symlink():
        raise ValueError('prepared source and marker must not be symlinks')
    if source.exists():
        metadata = json.loads(marker.read_text())
        if any(metadata.get(key) != value for key, value in expected.items()):
            raise ValueError('prepared source has a different version or patch; use a new directory')
        if tree_digest(source) != metadata.get('tree_sha256'):
            raise ValueError('prepared source changed; use a new private directory')
    else:
        staging = Path(tempfile.mkdtemp(prefix='prepare-', dir=directory))
        try:
            archive = supplied_archive
            if archive is None:
                archive = staging / 'upstream.tar.gz'
                with urllib.request.urlopen(ARCHIVE_URL, timeout=60) as response, archive.open('xb') as output:
                    if not response.geturl().startswith('https://'):
                        raise ValueError('source download requires HTTPS')
                    count = 0
                    while chunk := response.read(1024 * 1024):
                        count += len(chunk)
                        if count > MAX_COMPRESSED:
                            raise ValueError('source archive exceeds download limit')
                        output.write(chunk)
            if not archive.is_file() or archive.stat().st_size > MAX_COMPRESSED or digest(archive) != ARCHIVE_SHA256:
                raise ValueError('official ExtendDB source SHA-256 mismatch')
            tree = staging / 'source'
            tree.mkdir(mode=0o700)
            unpack(archive, tree)
            environment = {name: value for name, value in os.environ.items() if not name.startswith('GIT_')}
            environment.update(GIT_CEILING_DIRECTORIES=str(tree.parent),
                               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
            for patch in PATCHES:
                for arguments in (['--check'], []):
                    subprocess.run(['git', 'apply', *arguments, str(patch)], cwd=tree,
                                   env=environment, check=True, capture_output=True)
            expected['tree_sha256'] = tree_digest(tree)
            tree.rename(source)
            marker.write_text(json.dumps(expected, indent=2) + '\n')
        finally:
            shutil.rmtree(staging)
    config = directory / 'cargo-patch.toml'
    config.write_text('[patch."https://github.com/ExtendDB/extenddb"]\n' + ''.join(
        f'extenddb-{name} = {{ path = {json.dumps(str(source / "crates" / name))} }}\n'
        for name in PACKAGES))
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path,
                        default=ROOT / 'compatibility-tests/.work/extenddb-worker-source')
    parser.add_argument('--archive', type=Path, help='Use the pinned archive offline')
    args = parser.parse_args()
    try:
        config = prepare(args.directory, args.archive)
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as error:
        parser.exit(1, f'Cannot prepare ExtendDB source: {type(error).__name__}. Check the private directory, source checksum and patch compatibility.\n')
    print(config)


if __name__ == '__main__':
    main()
