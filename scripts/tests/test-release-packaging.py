#!/usr/bin/env python3
"""Check release guards and the AppImage entry point without building Rust."""
import os
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ReleasePackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "source with spaces"
        (self.repo / "scripts").mkdir(parents=True)
        for name in ("package-version.sh", "check-release-version.sh"):
            shutil.copy(ROOT / "scripts" / name, self.repo / "scripts" / name)
        (self.repo / "Cargo.toml").write_text('[workspace.package]\nversion = "0.1.2"\n')
        self.run_command("git", "init", "--quiet")
        self.run_command("git", "add", "Cargo.toml")
        self.run_command("git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                         "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                         "commit", "--quiet", "-m", "fixture")

    def run_command(self, *args):
        return subprocess.run(args, cwd=self.repo, text=True, capture_output=True, check=True)

    def check_version(self, *tags):
        return subprocess.run(["bash", "scripts/check-release-version.sh", *tags],
                              cwd=self.repo, text=True, capture_output=True)

    def test_proposed_tag_must_match_manifest(self):
        self.assertEqual(self.check_version("v0.1.2").returncode, 0)
        result = self.check_version("v0.1.3")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match Cargo.toml (v0.1.2)", result.stderr)

    def test_branch_detects_mismatched_tag_on_same_commit(self):
        self.assertEqual(self.check_version().returncode, 0)
        self.run_command("git", "tag", "v0.1.3")
        self.assertNotEqual(self.check_version().returncode, 0)

    def test_matching_tag_and_unrelated_tags_pass(self):
        self.run_command("git", "tag", "v0.1.2")
        self.run_command("git", "tag", "unrelated")
        self.assertEqual(self.check_version().returncode, 0)

    def test_prerelease_tag(self):
        (self.repo / "Cargo.toml").write_text('[workspace.package]\nversion = "0.1.3-rc.1"\n')
        self.assertEqual(self.check_version("v0.1.3-rc.1").returncode, 0)
        self.assertNotEqual(self.check_version("v0.1.3").returncode, 0)

    def test_apprun_preserves_arguments_and_working_directory(self):
        appdir = self.repo / "test.AppDir"
        binary = appdir / "usr/bin/locallycloud"
        binary.parent.mkdir(parents=True)
        shutil.copy(ROOT / "packaging/appimage/AppRun", appdir / "AppRun")
        binary.write_text('#!/bin/sh\npwd\nprintf "<%s>\\n" "$@"\n')
        binary.chmod(0o755)
        env = dict(os.environ)
        env.pop("APPDIR", None)
        for explicit_appdir in (False, True):
            if explicit_appdir:
                env["APPDIR"] = str(appdir)
            result = subprocess.run(["sh", str(appdir / "AppRun"), "--example", "a b", ""],
                                    cwd=self.repo, env=env, text=True, capture_output=True, check=True)
            self.assertEqual(result.stdout.splitlines(), [str(self.repo), "<--example>", "<a b>", "<>"])

    def test_complete_bundle_and_missing_appimage(self):
        dist = self.repo / "dist"
        dist.mkdir()
        inventory = {"bomFormat": "CycloneDX", "specVersion": "1.5",
                     "metadata": {"component": {"name": "locallycloud"}}, "components": [{}]}
        for name, suffix in (("locallycloud_0.1.3~rc.1-1_amd64", ".deb"),
                             ("locallycloud_0.1.3~rc.1-1_arm64", ".deb"),
                             ("locallycloud-0.1.3rc.1-1-x86_64", ".pkg.tar.zst"),
                             ("locallycloud-0.1.3-rc.1-x86_64", ".AppImage"),
                             ("locallycloud-0.1.3-rc.1-aarch64", ".AppImage")):
            (dist / (name + suffix)).write_bytes(b"package fixture")
            (dist / (name + ".cdx.json")).write_text(json.dumps(inventory))
        inventory["metadata"]["component"]["name"] = "locallycloud-extenddb-worker"
        for arch in ("x86_64", "arm64"):
            artifact = {"architecture": arch}
            for kind, suffix in (("binary", ""), ("notices", ".LICENSES.txt")):
                name = f"locallycloud-extenddb-worker-linux-{arch}{suffix}"
                body = b"worker fixture"
                (dist / name).write_bytes(body)
                artifact[kind] = {"name": name, "size": len(body),
                                  "sha256": hashlib.sha256(body).hexdigest()}
            (dist / f"extenddb-{arch}.json").write_text(json.dumps({"artifacts": [artifact]}))
            (dist / f"extenddb-{arch}.cdx.json").write_text(json.dumps(inventory))
        command = ["bash", str(ROOT / "scripts/prepare-release-assets.sh")]
        subprocess.run(command, cwd=dist, capture_output=True, check=True)
        sums = (dist / "SHA256SUMS").read_text()
        self.assertIn("locallycloud_0.1.3.rc.1-1_amd64.deb", sums)
        self.assertEqual(sums.count(".AppImage"), 2)
        (dist / "locallycloud-0.1.3-rc.1-aarch64.AppImage").unlink()
        result = subprocess.run(command, cwd=dist, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Expected x86_64 and aarch64 AppImages", result.stderr)


if __name__ == "__main__":
    unittest.main()
