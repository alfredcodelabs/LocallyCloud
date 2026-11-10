#!/usr/bin/env python3
"""Inspect and import pinned upstream Lambda and PostgreSQL images without a container daemon."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import gzip
import io
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import platform
import re
import shutil
import stat
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

REGISTRY = "https://public.ecr.aws"
REPOSITORY = "lambda/nodejs"
BLOBS = None
RUNTIME_PATTERNS = {
    "lambda/nodejs": r"nodejs([1-9][0-9]?)\.x",
    "lambda/python": r"python(3\.[0-9]{1,2})",
    "lambda/ruby": r"ruby([1-9][0-9]?\.[0-9]{1,2})",
    "lambda/dotnet": r"dotnet([1-9][0-9]?)",
    "lambda/provided": r"provided\.(al2|al2023)",
    "docker/library/postgres": r"postgres(16|17|18)",
}
ACCEPT = ", ".join((
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
))
ROOT = Path(__file__).resolve().parents[1] if "__file__" in globals() else Path.cwd()
WORK = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "locallycloud/lambda/runtime-import"


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        redirected = super().redirect_request(request, response, code, message, headers, url)
        if redirected and urllib.parse.urlsplit(request.full_url).netloc != urllib.parse.urlsplit(url).netloc:
            redirected.remove_header("Authorization")
        return redirected


class Registry:
    def __init__(self):
        self.opener = urllib.request.build_opener(SafeRedirect())
        data, _ = self.get(
            REGISTRY + "/token/?service=public.ecr.aws&scope=repository:" + REPOSITORY + ":pull",
            authenticated=False,
        )
        payload = json.loads(data)
        self.token = payload.get("token") or payload["access_token"]

    def open(self, url, authenticated=True):
        headers = {"Accept": ACCEPT}
        if authenticated:
            headers["Authorization"] = "Bearer " + self.token
        return self.opener.open(urllib.request.Request(url, headers=headers), timeout=60)

    def get(self, url, authenticated=True, limit=8 * 1024 * 1024):
        with self.open(url, authenticated) as response:
            body = response.read(limit + 1)
            if len(body) > limit:
                raise ValueError("Registry metadata exceeds its bound")
            return body, response.headers

    def manifest(self, reference):
        raw, headers = self.get(f"{REGISTRY}/v2/{REPOSITORY}/manifests/{reference}")
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        declared = headers.get("Docker-Content-Digest")
        if declared and declared != digest:
            raise ValueError("Manifest checksum differs from registry declaration")
        if reference.startswith("sha256:") and reference != digest:
            raise ValueError("Pinned manifest checksum mismatch")
        return json.loads(raw), digest

    def blob_metadata(self, descriptor):
        raw, _ = self.get(f"{REGISTRY}/v2/{REPOSITORY}/blobs/{descriptor['digest']}")
        if "sha256:" + hashlib.sha256(raw).hexdigest() != descriptor["digest"]:
            raise ValueError("Configuration checksum mismatch")
        if len(raw) != descriptor["size"]:
            raise ValueError("Configuration length mismatch")
        return json.loads(raw)


def write_json(path, value):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("x") as output:
        output.write(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for data in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(data)
    return "sha256:" + digest.hexdigest()


@contextmanager
def layer_lock(path):
    """Keep lock files stable: unlinking one can let writers lock different inodes."""
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1 or status.st_uid != os.geteuid():
            raise ValueError("Layer lock must be a private, owned regular file")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def download_layer(registry, layer, blobs):
    digest = layer["digest"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("Unsupported layer digest")
    path = blobs / (digest.split(":", 1)[1] + ".tar.gz")
    with layer_lock(path.with_suffix(".lock")):
        if path.exists() and path.stat().st_size == layer["size"] and checksum(path) == digest:
            return
        partial = path.with_name(path.name + "." + uuid.uuid4().hex + ".part")
        try:
            total = 0
            with registry.open(f"{REGISTRY}/v2/{REPOSITORY}/blobs/{digest}") as response:
                descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, "wb") as output:
                    while data := response.read(1024 * 1024):
                        total += len(data)
                        if total > layer["size"]:
                            raise ValueError("Layer exceeds manifest length")
                        output.write(data)
            if total != layer["size"] or checksum(partial) != digest:
                raise ValueError("Layer integrity verification failed")
            partial.replace(path)
        finally:
            partial.unlink(missing_ok=True)


def member_path(name):
    if not name or "\x00" in name or "\\" in name or len(name) > 4096:
        raise ValueError("Unsafe archive path")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("Archive member escapes image root")
    return path


class BoundedReader(io.RawIOBase):
    def __init__(self, source, limit):
        self.source, self.limit, self.used = source, limit, 0

    def readable(self):
        return True

    def read(self, size=-1):
        if size < 0 or size > 8 * 1024 * 1024:
            raise ValueError("Unbounded archive read")
        data = self.source.read(size)
        self.used += len(data)
        if self.used > self.limit:
            raise ValueError("Expanded archive exceeds budget")
        return data


class ImageRoot:
    """Resolve guest-root absolute links without ever following them into the host."""
    def __init__(self, root):
        self.root = root
        self.entries = 0
        self.expanded = 0
        self.directory_modes = {}

    def path(self, name, follow_final=True):
        pending = list(member_path(name).parts)
        resolved, links = [], 0
        while pending:
            part = pending.pop(0)
            if part in ("", "."):
                continue
            if part == "..":
                if not resolved:
                    raise ValueError("Link escapes guest root")
                resolved.pop()
                continue
            candidate = self.root.joinpath(*resolved, part)
            if candidate.is_symlink() and (pending or follow_final):
                links += 1
                if links > 40:
                    raise ValueError("Archive symlink cycle")
                target = PurePosixPath(os.readlink(candidate))
                if len(str(target)) > 4096 or "\\" in str(target):
                    raise ValueError("Unsafe link target")
                if target.is_absolute():
                    resolved = []
                    target = target.relative_to("/")
                pending = list(target.parts) + pending
            else:
                resolved.append(part)
        return self.root.joinpath(*resolved)

    def remove(self, path):
        if path == self.root:
            raise ValueError("Cannot remove image root")
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.exists():
            shutil.rmtree(path)

    def scan(self, blob, budget, max_entries):
        names = []
        with gzip.open(blob, "rb") as source:
            bounded = BoundedReader(source, budget - self.expanded)
            with tarfile.open(fileobj=bounded, mode="r|") as archive:
                for entry in archive:
                    name = PurePosixPath(".") if entry.name == "" and entry.isdir() else member_path(entry.name)
                    self.entries += 1
                    if self.entries > max_entries or entry.size > budget:
                        raise ValueError("Archive entry budget exceeded")
                    if not (entry.isdir() or entry.isfile() or entry.issym() or entry.islnk()
                            or name.name.startswith(".wh.")):
                        raise ValueError("Special archive node is unsupported")
                    names.append(name)
            self.expanded += bounded.used
        return names

    def apply(self, blob, budget, max_entries):
        names = self.scan(blob, budget, max_entries)
        # OCI whiteouts affect lower layers, including when appearing late in the tar.
        for name in names:
            if not name.name.startswith(".wh."):
                continue
            parent = self.path(str(name.parent))
            if name.name == ".wh..wh..opq":
                if parent.is_dir():
                    for child in parent.iterdir():
                        self.remove(child)
            else:
                target = name.name[4:]
                if target in ("", ".", ".."):
                    raise ValueError("Invalid whiteout")
                self.remove(self.path(str(name.parent / target), follow_final=False))
        hardlinks = []
        with gzip.open(blob, "rb") as source:
            with tarfile.open(fileobj=BoundedReader(source, budget), mode="r|") as archive:
                for entry in archive:
                    name = PurePosixPath(".") if entry.name == "" and entry.isdir() else member_path(entry.name)
                    if name.name.startswith(".wh.") or not name.parts:
                        continue
                    if entry.isdir():
                        destination = self.path(str(name))
                        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                        self.directory_modes[destination] = entry.mode & 0o1777
                        continue
                    destination = self.path(str(name), follow_final=False)
                    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    self.remove(destination)
                    if entry.issym():
                        if len(entry.linkname) > 4096 or "\x00" in entry.linkname or "\\" in entry.linkname:
                            raise ValueError("Unsafe symlink")
                        destination.symlink_to(entry.linkname)
                        self.path(str(name))  # Validate target with guest-root semantics.
                    elif entry.islnk():
                        hardlinks.append((destination, entry.linkname))
                    elif entry.isfile():
                        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                        with os.fdopen(descriptor, "wb") as output, archive.extractfile(entry) as data:
                            shutil.copyfileobj(data, output, 1024 * 1024)
                        destination.chmod(entry.mode & 0o777)
        for destination, target in hardlinks:
            source = self.path(target)
            if not stat.S_ISREG(source.lstat().st_mode):
                raise ValueError("Hardlink source is not a regular file")
            os.link(source, destination, follow_symlinks=False)

    def finish(self):
        for path, mode in sorted(self.directory_modes.items(), key=lambda p: len(p[0].parts), reverse=True):
            if path.exists() and not path.is_symlink():
                path.chmod(mode)


def download_and_extract(max_compressed, max_expanded, max_entries):
    global REPOSITORY
    info = json.loads((WORK / "inspection.json").read_text())
    REPOSITORY = info.get("repository", "lambda/nodejs")
    if REPOSITORY not in RUNTIME_PATTERNS:
        raise ValueError("Only supported upstream runtime repositories are supported")
    registry = Registry()
    manifest, digest = registry.manifest(info["imageDigest"])
    if digest != info["imageDigest"] or manifest["layers"] != info["layers"]:
        raise ValueError("Image metadata changed")
    if sum(layer["size"] for layer in info["layers"]) > max_compressed:
        raise ValueError("Compressed image exceeds approved budget")
    blobs = BLOBS or WORK / "blobs"
    blobs.mkdir(parents=True, exist_ok=True)
    for index, layer in enumerate(info["layers"]):
        if layer["mediaType"] not in {"application/vnd.docker.image.rootfs.diff.tar.gzip", "application/vnd.oci.image.layer.v1.tar+gzip"}:
            raise ValueError("Unsupported layer compression")
        download_layer(registry, layer, blobs)
        print(f"Verified layer {index + 1}/{len(info['layers'])}: {layer['size']} bytes", flush=True)
    destination = WORK / "rootfs"
    if destination.exists():
        raise ValueError("Rootfs already exists; refusing to overwrite it")
    stage = WORK / ("rootfs-stage-" + uuid.uuid4().hex)
    stage.mkdir(mode=0o700)
    root = ImageRoot(stage)
    started = time.monotonic()
    try:
        for layer in info["layers"]:
            blob = blobs / (layer["digest"].split(":", 1)[1] + ".tar.gz")
            root.apply(blob, max_expanded, max_entries)
        root.finish()
        stage.rename(destination)
    except BaseException:
        shutil.rmtree(stage)
        raise
    stats = {"imageDigest": info["imageDigest"], "entries": root.entries,
             "expandedArchiveBytes": root.expanded, "extractionSeconds": time.monotonic() - started,
             "rootfs": str(destination), "symlinkHandling": "Preserved guest links; extraction resolves them within guest root"}
    write_json(WORK / "extraction.json", stats)
    print(json.dumps(stats, indent=2))


def resolve_image(reference, architecture, runtime):
    registry = Registry()
    top, top_digest = registry.manifest(reference)
    image, image_digest = top, top_digest
    if "manifests" in top:
        matching = [entry for entry in top["manifests"]
                    if entry.get("platform", {}).get("os") == "linux"
                    and entry.get("platform", {}).get("architecture") == architecture]
        if len(matching) != 1:
            raise ValueError("No unique Linux architecture image in manifest index")
        image, image_digest = registry.manifest(matching[0]["digest"])
    config = registry.blob_metadata(image["config"])
    if config.get("architecture") != architecture or config.get("os") != "linux":
        raise ValueError("Image platform does not match requested architecture")
    result = {
        "source": f"{REGISTRY}/{REPOSITORY}" + ("@" if reference.startswith("sha256:") else ":") + reference,
        "repository": REPOSITORY,
        "runtime": runtime,
        "topDigest": top_digest,
        "imageDigest": image_digest,
        "architecture": architecture,
        "compressedLayerBytes": sum(layer["size"] for layer in image["layers"]),
        "layers": image["layers"],
        "configDigest": image["config"]["digest"],
        "runtimeConfig": config.get("config", {}),
        "created": config.get("created"),
    }
    return result, image, config


def inspect(reference, architecture, runtime):
    result, image, config = resolve_image(reference, architecture, runtime)
    WORK.mkdir(parents=True, exist_ok=True)
    os.chmod(WORK, 0o700)
    if (WORK / "rootfs").exists() and (WORK / "inspection.json").exists():
        previous = json.loads((WORK / "inspection.json").read_text())
        if previous["imageDigest"] != result["imageDigest"]:
            raise ValueError("A different image is already extracted; use a separate private workspace")
    write_json(WORK / "inspection.json", result)
    write_json(WORK / "image-manifest.json", image)
    write_json(WORK / "config.json", config)
    print(json.dumps(result, indent=2))


def check_updates():
    """Read upstream metadata without changing a live pack or downloading layers."""
    global REPOSITORY
    manifest = json.loads((WORK / "manifest.json").read_text())
    REPOSITORY = manifest["source"]["repository"]
    pattern = RUNTIME_PATTERNS.get(REPOSITORY)
    match = re.fullmatch(pattern, manifest["runtime"]) if pattern else None
    architecture = {"x86_64": "amd64", "arm64": "arm64"}.get(manifest["architecture"])
    if not match or not architecture:
        raise ValueError("Installed pack has an invalid official runtime identity")
    reference = match.group(1) + ("-bookworm" if REPOSITORY == "docker/library/postgres" else "")
    current, _, _ = resolve_image(reference, architecture, manifest["runtime"])
    return {"runtime": manifest["runtime"], "architecture": manifest["architecture"],
            "installedDigest": manifest["source"]["imageDigest"],
            "availableDigest": current["imageDigest"],
            "updateAvailable": manifest["source"]["imageDigest"] != current["imageDigest"]}


def pack(runtime):
    """Record the complete guest tree without following guest absolute links."""
    info = json.loads((WORK / "inspection.json").read_text())
    runtime = runtime or info.get("runtime")
    repository = info.get("repository", "lambda/nodejs")
    if not runtime or not re.fullmatch(RUNTIME_PATTERNS.get(repository, r"(?!)"), runtime):
        raise ValueError("Explicit runtime name must match the official repository")
    root = WORK / "rootfs"
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Pack requires an extracted rootfs directory")
    entries = []
    def walk_error(error):
        raise error

    for directory, directories, files in os.walk(root, followlinks=False, onerror=walk_error):
        for name in sorted(directories + files):
            path = Path(directory) / name
            status = path.lstat()
            entry = {"path": path.relative_to(root).as_posix(), "mode": stat.S_IMODE(status.st_mode)}
            if stat.S_ISLNK(status.st_mode):
                entry.update(kind="symlink", target=os.readlink(path))
            elif stat.S_ISDIR(status.st_mode):
                mode = stat.S_IMODE(status.st_mode) | stat.S_IRUSR | stat.S_IXUSR
                path.chmod(mode)
                entry.update(kind="directory", mode=mode)
            elif stat.S_ISREG(status.st_mode):
                # Rootless import must retain read access for integrity verification.
                mode = stat.S_IMODE(status.st_mode) | stat.S_IRUSR
                path.chmod(mode)
                entry.update(kind="file", mode=mode, sha256=checksum(path))
            else:
                raise ValueError("Pack contains an unsupported filesystem node")
            entries.append(entry)
    entries.sort(key=lambda entry: entry["path"])
    write_json(WORK / "inventory.json", entries)
    config = info["runtimeConfig"]
    environment = dict(item.split("=", 1) for item in config.get("Env", []))
    result = {
        "schemaVersion": 1, "runtime": runtime,
        "architecture": {"amd64": "x86_64", "arm64": "arm64"}[info["architecture"]],
        "rootfs": "rootfs", "inventory": "inventory.json",
        "inventorySha256": checksum(WORK / "inventory.json"),
        "source": {"registry": "public.ecr.aws", "repository": repository,
                   "indexDigest": info["topDigest"], "imageDigest": info["imageDigest"],
                   "configDigest": info["configDigest"]},
        "entrypoint": config.get("Entrypoint", []), "environment": environment,
        "workingDirectory": config.get("WorkingDir") or ("/" if repository == "docker/library/postgres" else "/var/task"),
    }
    write_json(WORK / "manifest.json", result)
    print(json.dumps({"packManifest": str(WORK / "manifest.json"), "entries": len(entries),
                      "inventorySha256": result["inventorySha256"]}, indent=2))


def main():
    global WORK, REPOSITORY, BLOBS
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        "Inspect first, review compressedLayerBytes, then import with explicit bounds. "
        "Use --work <packs>/<runtime>/<x86_64|arm64> and --runtime to publish a local pack. "
        "No downloads occur inside the server. The pack command inventories an existing rootfs."))
    parser.add_argument("command", choices=["inspect", "import", "pack", "check"])
    parser.add_argument("--runtime", help="Runtime name, e.g. nodejs22.x, python3.13, provided.al2023, postgres16")
    parser.add_argument("--repository", choices=[repository.rsplit("/", 1)[1] for repository in RUNTIME_PATTERNS], default="nodejs")
    parser.add_argument("--reference", default="22")
    parser.add_argument("--blobs", type=Path, help="Shared content-addressed layer cache")
    parser.add_argument("--architecture", choices=["amd64", "arm64"],
                        default={"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine()))
    parser.add_argument("--max-compressed", type=int, default=150 * 1024 * 1024)
    parser.add_argument("--max-expanded", type=int, default=1024 * 1024 * 1024)
    parser.add_argument("--max-entries", type=int, default=100000)
    parser.add_argument("--work", type=Path, default=WORK)
    args = parser.parse_args()
    WORK = args.work.resolve()
    REPOSITORY = next(repository for repository in RUNTIME_PATTERNS if repository.rsplit("/", 1)[1] == args.repository)
    BLOBS = args.blobs.resolve() if args.blobs else None
    for location in [args.work.absolute(), args.blobs.absolute() if args.blobs else None]:
        if location and any(part.is_symlink() for part in [location, *location.parents]):
            raise ValueError("Pack and cache paths must not contain symlinks")
    if not re.fullmatch(r"(?:sha256:[0-9a-f]{64}|[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})", args.reference):
        raise ValueError("Invalid image tag or digest")
    if min(args.max_compressed, args.max_expanded, args.max_entries) <= 0:
        raise ValueError("Import bounds must be positive")
    if not args.architecture:
        raise ValueError("Unsupported host architecture")
    if args.command == "inspect":
        inspect(args.reference, args.architecture, args.runtime)
    elif args.command == "import":
        download_and_extract(args.max_compressed, args.max_expanded, args.max_entries)
        if args.runtime:
            pack(args.runtime)
    elif args.command == "check":
        print(json.dumps(check_updates(), indent=2))
    else:
        pack(args.runtime)


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as error:
        raise SystemExit(f"Public registry request failed (HTTP {error.code}); credentials and URLs omitted")
    except urllib.error.URLError:
        raise SystemExit("Public registry connection failed; credentials and URLs omitted")
