"""Small offline regressions for the disposable OCI artifact importer."""
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

import importlib.util
import sys
from unittest import mock

sys.dont_write_bytecode = True
import json
import contextlib
import hashlib
import multiprocessing
import os
_spec = importlib.util.spec_from_file_location("artifact", Path(__file__).resolve().parents[1] / "import-lambda-runtime.py")
artifact = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(artifact)
artifact.WORK = artifact.ROOT / "compatibility-tests/.work/runtime-import-tests"


class ArtifactTest(unittest.TestCase):
    def test_official_runtime_identity_and_update_tag(self):
        import re
        for repository, runtime, tag in [
            ("docker/library/postgres", "postgres16", "16-bookworm"),
            ("lambda/nodejs", "nodejs24.x", "24"),
            ("lambda/python", "python3.14", "3.14"),
            ("lambda/ruby", "ruby4.0", "4.0"),
            ("lambda/ruby", "ruby3.4", "3.4"),
            ("lambda/dotnet", "dotnet10", "10"),
            ("lambda/provided", "provided.al2023", "al2023"),
        ]:
            with self.subTest(runtime=runtime):
                self.assertEqual(re.fullmatch(artifact.RUNTIME_PATTERNS[repository], runtime).group(1) + ("-bookworm" if repository == "docker/library/postgres" else ""), tag)
                manifest = {"runtime": runtime, "architecture": "x86_64",
                            "source": {"repository": repository, "imageDigest": "old"}}
                (self.work / "manifest.json").write_text(json.dumps(manifest))
                with mock.patch.object(artifact, "WORK", self.work), mock.patch.object(artifact, "resolve_image", return_value=({"imageDigest": "new"}, {}, {})) as resolve:
                    self.assertTrue(artifact.check_updates()["updateAvailable"])
                    resolve.assert_called_once_with(tag, "amd64", runtime)
        self.assertIsNone(re.fullmatch(artifact.RUNTIME_PATTERNS["lambda/ruby"], "ruby4.0/../../"))

    def test_concurrent_downloaders_recheck_shared_cache_under_layer_lock(self):
        context = multiprocessing.get_context("fork")
        blobs = self.work / "blobs"
        blobs.mkdir()
        payload = b"verified shared cache content" * 100
        layer = {"digest": "sha256:" + hashlib.sha256(payload).hexdigest(), "size": len(payload)}
        path = blobs / (layer["digest"].split(":")[1] + ".tar.gz")
        path.write_bytes(b"truncated")
        downloads = context.Value("i", 0)
        entered, release, second_ready, duplicate = [context.Event() for _ in range(4)]

        class FakeRegistry:
            def open(self, url):
                with downloads.get_lock():
                    downloads.value += 1
                    if downloads.value > 1:
                        duplicate.set()
                entered.set()
                if not release.wait(5):
                    raise RuntimeError("Test did not release the fake registry")
                return io.BytesIO(payload)

        def download(second=False):
            if second:
                second_ready.set()
            artifact.download_layer(FakeRegistry(), layer, blobs)

        first = context.Process(target=download)
        second = context.Process(target=download, args=(True,))
        first.start()
        try:
            self.assertTrue(entered.wait(5))
            second.start()
            self.assertTrue(second_ready.wait(5))
            self.assertFalse(duplicate.wait(0.25))
        finally:
            release.set()
            for process in (first, second):
                if process.pid:
                    process.join(5)
                    if process.is_alive():
                        process.kill()
                        process.join()
        self.assertEqual((first.exitcode, second.exitcode), (0, 0))
        self.assertEqual(downloads.value, 1)
        self.assertEqual(path.read_bytes(), payload)
        self.assertFalse(list(blobs.glob("*.part")))
        self.assertEqual(path.with_suffix(".lock").stat().st_mode & 0o777, 0o600)

    def test_download_interrupt_cleans_partial_and_releases_lock(self):
        payload = b"complete"
        layer = {"digest": "sha256:" + hashlib.sha256(payload).hexdigest(), "size": len(payload)}

        class Interrupted(io.BytesIO):
            def read(self, size):
                raise KeyboardInterrupt()

        registry = mock.Mock()
        registry.open.return_value = Interrupted(payload)
        with self.assertRaises(KeyboardInterrupt):
            artifact.download_layer(registry, layer, self.work)
        self.assertFalse(list(self.work.glob("*.part")))
        registry.open.return_value = io.BytesIO(payload)
        artifact.download_layer(registry, layer, self.work)
        self.assertEqual(artifact.checksum(self.work / (layer["digest"].split(":")[1] + ".tar.gz")), layer["digest"])

    def test_layer_locks_reject_symlinks_and_hardlinks(self):
        target = self.work / "target"
        target.write_bytes(b"untouched")
        link = self.work / "layer.lock"
        link.symlink_to(target)
        with self.assertRaises(OSError):
            with artifact.layer_lock(link):
                self.fail("Symlink lock accepted")
        link.unlink()
        os.link(target, link)
        with self.assertRaises(ValueError):
            with artifact.layer_lock(link):
                self.fail("Hardlinked lock accepted")
        self.assertEqual(target.read_bytes(), b"untouched")

    def test_update_check_is_read_only_and_detects_new_digest(self):
        previous = artifact.WORK
        previous_repository = artifact.REPOSITORY
        artifact.WORK = self.work
        self.addCleanup(setattr, artifact, "WORK", previous)
        self.addCleanup(setattr, artifact, "REPOSITORY", previous_repository)
        manifest = {"runtime":"python3.13","architecture":"x86_64","source":{"repository":"lambda/python","imageDigest":"sha256:old"}}
        artifact.write_json(self.work / "manifest.json", manifest)
        before = (self.work / "manifest.json").read_bytes()
        with mock.patch.object(artifact, "resolve_image", return_value=({"imageDigest":"sha256:new"},{},{})) as resolve:
            result = artifact.check_updates()
        self.assertTrue(result["updateAvailable"])
        resolve.assert_called_once_with("3.13", "amd64", "python3.13")
        self.assertEqual((self.work / "manifest.json").read_bytes(), before)
        self.assertFalse((self.work / "inspection.json").exists())

    def setUp(self):
        test_work = artifact.ROOT / "compatibility-tests/.work/runtime-import-tests"
        test_work.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.temporary = tempfile.TemporaryDirectory(dir=test_work)
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.root = self.work / "image"
        self.root.mkdir()

    def layer(self, entries):
        path = self.work / (str(len(list(self.work.glob("*.tgz")))) + ".tgz")
        with tarfile.open(path, "w:gz") as archive:
            for name, content in entries:
                entry = tarfile.TarInfo(name)
                entry.size = len(content)
                archive.addfile(entry, io.BytesIO(content))
        return path

    def test_pack_inventory_matches_files_and_guest_links(self):
        previous = artifact.WORK
        artifact.WORK = self.work
        self.addCleanup(setattr, artifact, "WORK", previous)
        self.root.rename(self.work / "rootfs")
        root = self.work / "rootfs"
        (root / "file").write_bytes(b"verified")
        (root / "file").chmod(0)
        (root / "link").symlink_to("/file")
        artifact.write_json(self.work / "inspection.json", {
            "repository": "lambda/nodejs", "architecture": "amd64",
            "topDigest": "sha256:" + "a" * 64, "imageDigest": "sha256:" + "b" * 64,
            "configDigest": "sha256:" + "c" * 64,
            "runtimeConfig": {"Env": ["EXAMPLE=value"], "Entrypoint": ["/lambda-entrypoint.sh"]},
        })
        with contextlib.redirect_stdout(io.StringIO()):
            artifact.pack("nodejs22.x")
        manifest = json.loads((self.work / "manifest.json").read_text())
        self.assertEqual(manifest["inventorySha256"], artifact.checksum(self.work / "inventory.json"))
        inventory = json.loads((self.work / "inventory.json").read_text())
        self.assertEqual(inventory[0]["sha256"], artifact.checksum(root / "file"))
        self.assertEqual(inventory[1]["target"], "/file")
        self.assertEqual(manifest["environment"], {"EXAMPLE": "value"})

    def test_guest_absolute_links_never_follow_host_paths(self):
        (self.root / "usr/bin").mkdir(parents=True)
        (self.root / "bin").symlink_to("/usr/bin")
        image = artifact.ImageRoot(self.root)
        image.apply(self.layer([("bin/probe", b"guest")]), 100000, 10)
        self.assertEqual((self.root / "usr/bin/probe").read_bytes(), b"guest")
        (self.root / "escape").symlink_to("../../outside")
        with self.assertRaises(ValueError):
            image.path("escape/probe")

    def test_whiteouts_apply_to_lower_layer_not_same_layer_files(self):
        image = artifact.ImageRoot(self.root)
        image.apply(self.layer([("data/old", b"old"), ("gone", b"old")]), 100000, 20)
        image.apply(self.layer([("data/new", b"new"), ("data/.wh..wh..opq", b""),
                                (".wh.gone", b"")]), 100000, 20)
        self.assertFalse((self.root / "data/old").exists())
        self.assertFalse((self.root / "gone").exists())
        self.assertEqual((self.root / "data/new").read_bytes(), b"new")

    def test_traversal_and_expansion_fail_before_materializing_files(self):
        image = artifact.ImageRoot(self.root)
        with self.assertRaises(ValueError):
            image.apply(self.layer([("../escape", b"x")]), 100000, 10)
        self.assertFalse((self.work / "escape").exists())
        with self.assertRaises(ValueError):
            image.apply(self.layer([("oversized", b"x" * 20000)]), 1024, 10)
        self.assertFalse((self.root / "oversized").exists())


if __name__ == "__main__":
    unittest.main()
