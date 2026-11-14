# Versioning and packages

The product version is chosen manually in `[workspace.package].version` in `Cargo.toml`. All workspace crates inherit that version. Debian and the Arch checkout package derive it automatically using `scripts/package-version.sh`.

We use three components, `MAJOR.MINOR.PATCH`, with no leading zeros. Prerelease channels use `-alpha.N`, `-beta.N`, or `-rc.N`, with N starting at 1. The `v` prefix is used only for Git tags.

Debian package versions retain `~` in their control metadata. GitHub Release
asset names replace `~` with `.`, so the release workflow renames affected files
before calculating `SHA256SUMS`. For example, the public first-beta download is
`locallycloud_0.1.0.beta.1-1_amd64.deb`, with internal version
`0.1.0~beta.1-1`. This filename change does not change package contents or version
ordering. Local build outputs and APT repository pool files retain `~`.

| Release | Cargo | Git tag | Debian, revision 1 | Arch, pkgrel 1 |
| --- | --- | --- | --- | --- |
| First beta | `0.1.0-beta.1` | `v0.1.0-beta.1` | `0.1.0~beta.1-1` | `0.1.0beta.1-1` |
| Release without a beta suffix | `0.1.0` | `v0.1.0` | `0.1.0-1` | `0.1.0-1` |
| Subsequent patch | `0.1.1` | `v0.1.1` | `0.1.1-1` | `0.1.1-1` |

`0.1.0.1` and `0.1.01.1` are rejected. A release without a beta suffix in `0.x` is still initial development; API stability is declared at `1.0.0`.

## Inspect and validate

```sh
bash scripts/package-version.sh product
bash scripts/package-version.sh tag
bash scripts/package-version.sh arch
bash scripts/package-version.sh debian
bash scripts/check-package-version.sh
```

For a new version, edit Cargo.toml and update Cargo.lock with
`cargo update --workspace --offline`. Commit both before following the
[release steps](#publish-a-release). The tag must match the committed version.

## Local release checks

Use cargo-audit 0.23.0, cargo-cyclonedx 0.5.10 and AWS CLI v2. These commands do not build the product:

```sh
bash scripts/check-dependencies.sh
bash scripts/generate-sbom.sh crates/server/Cargo.toml /path/to/locallycloud.cdx.json
python3 scripts/validate-upgrade.py --previous /path/to/previous/locallycloud --candidate target/release/locallycloud --work-dir /disk/new-upgrade-check
```

The upgrade probe uses private state: S3 versions, native DynamoDB, SQS and Logs
in two regions, plus global IAM. It restarts the candidate and records binary hashes,
startup time and memory in `report.json`; it does not certify OCI or other databases.
SBOMs describe Rust dependencies. Native-library coverage and VM/OCI checks remain separate.
Dependency advisories block publication; review applicability before adding exceptions.

## 0.1.1 release

Tag: `v0.1.1`; packaging revision: 1. Includes CloudFormation lifecycle and Lambda
configuration fixes, Athena joins, KMS alias conditions and Catch-based DLQ detection.
See [service scope and limits](../docs/SERVICES.md). Publish after the workflow
gates below; preserve published tags. Update the [AUR recipe](#aur) after publication.

## 0.1.0 release

The release tag is `v0.1.0`, with packaging revision 1. It has no prerelease suffix and becomes the GitHub `latest` release only after the publishing workflow succeeds. Version `0.x` still permits API changes; this is not a declaration of `1.0` API stability.

Changes since beta.4 include:

- Official AWS Lambda runtime packs installed and updated explicitly through `locallycloud runtime`, without startup or invocation downloads.
- ExtendDB integration with durable global replication, Streams to Lambda, TTL, per-table KMS encryption, backups and native PITR history migration.
- Rootless OCI PostgreSQL packs for RDS and RDS Data API, supporting majors 16, 17 and 18 (default 18), with no required host PostgreSQL installation.
- Lambda-backed CloudFormation custom resource lifecycles, provisioning/cleanup fixes, API Gateway to Step Functions mappings, and Firehose/Iceberg routing.
- Dashboard architecture review and OWASP Threat Dragon import/export.

The functional candidate at `b780845` passed package installation and SDK/CLI smoke checks in QEMU on Debian 13 and Ubuntu 24.04/26.04, on both architectures: Lambda Node/Python/Go, S3/SQS, PostgreSQL 18 with UUIDv7, and SQL/S3 persistence after restart. Those checks do not replace CI or certify every service integration. Publishing still waits for the workflow gates below.

For current source-archive checksums and publication steps, see [AUR](#aur); do not invent checksums or use `SKIP`.

## Packaging revisions

If you fix only the package for an already published version, increment its revision: `pkgrel` for Arch and `LOCALLYCLOUD_DEBIAN_REVISION` for Debian. These revisions can evolve independently. Reset both to 1 for each new product version.

```sh
# Debian, revision 2 of the same product version:
LOCALLYCLOUD_DEBIAN_REVISION=2 bash packaging/debian/build-deb.sh /path/to/sqlite-autoconf-3540100.tar.gz
```

Keep revision 1 before the first publication.

## AUR

There are two Arch recipes. `packaging/arch/PKGBUILD` builds the local checkout and is what CI uses. `packaging/aur/PKGBUILD` is the AUR recipe: it downloads the release tag's source archive from GitHub, verifies its SHA-256, fetches crates and generates license notices in `prepare()`, builds offline with `--frozen`, runs the core library tests in `check()`, and installs the binary, license notices, man page, launcher, and icons.

After the release tag is published, on an Arch machine:

```sh
bash packaging/aur/update.sh            # tag derived from Cargo.toml, or pass one: v0.1.1
cd packaging/aur && makepkg --cleanbuild && namcap PKGBUILD ./*.pkg.tar.zst
```

`update.sh` sets `pkgver`, `_tag`, `pkgrel=1`, and `sha256sums` from the published archive and regenerates `.SRCINFO`. Copy `PKGBUILD` and `.SRCINFO` into the AUR Git repository (`ssh://aur@aur.archlinux.org/locallycloud.git`) and push them; the AUR account and its SSH key are configured separately from GitHub. For a packaging-only fix of the same release, increment `pkgrel` in both recipes and regenerate `.SRCINFO` with `makepkg --printsrcinfo > .SRCINFO`.

Run the build and package inspection in a disposable Arch VM before submitting
the recipe. The recipe builds from the published source archive, independently
of the binary package produced by CI. Only the recipe and `.SRCINFO` belong in
the AUR repository; build artifacts do not.

The first-beta archive predates the Zstandard C-library notice correction. Its
AUR `prepare()` applies the same verified two-file BSD clarification used in
`packaging/licenses/about.toml` only for `v0.1.0-beta.1`. Later tags already
contain the correction. When updating `zstd-sys`, refresh both license
hashes and check that generated notices retain the bindings and bundled-library
copyrights. The license helper rejects missing bundled Zstandard notices.

## APT repository

GitHub Release `.deb` files can be installed directly with `apt install ./file.deb`.
For `apt install locallycloud` and updates from a configured source, use
[the signed repository builder](apt/README.md). It validates the two release
packages and creates a `beta` suite for amd64 and arm64, with signed metadata and
a public keyring. Publication still needs an HTTPS host and a maintainer-owned
signing key. Preparing the files does not register the package with Debian or
Ubuntu's official repositories.

References: [SemVer](https://semver.org/), [Debian](https://www.debian.org/doc/debian-policy/ch-controlfields.html#version), [Arch](https://man.archlinux.org/man/PKGBUILD.5.en).

## GitHub Actions

[CI and packages](../.github/workflows/packages.yml) runs on pull requests, pushes
to `main`, `master`, `develop`, and `stage`, and `v*` tags. Manual runs check a
branch without publishing.

All runs validate versions, run formatting, workspace tests and Clippy, and check
the real ExtendDB worker and architecture review UI/MCP. Debian packages are built
natively in Debian 13 with static SQLite and a computed glibc dependency. Arch
uses its repository toolchain and SQLite. See [platform coverage](../docs/PLATFORMS.md#support-levels)
for the installation matrix; containers do not cover the required VM/WSL compute checks.

Branches also assemble `release-bundle`: packages, component metadata, Rust SBOMs
and verified `SHA256SUMS`. Only attestation and publication require a tag.

### Check a proposed tag

```sh
bash scripts/check-release-version.sh vX.Y.Z
```

Replace `vX.Y.Z` with the intended tag. The check rejects a mismatch with Cargo.toml.
Without an argument, it checks release tags already pointing at the current commit;
CI runs this check on branches and tags.

A green branch cannot validate a tag chosen later. To check one before pushing it,
run the workflow manually with `release_tag=vX.Y.Z`. The version job summary also
shows the tag derived from Cargo.toml.

### Build an AppImage

On the matching architecture, pass a `.deb` produced by
[build-deb.sh](debian/build-deb.sh):

```sh
bash packaging/appimage/build-appimage.sh target/debian-package/dist/locallycloud_VERSION_ARCH.deb
```

Replace `VERSION` with the Debian package version and `ARCH` with `amd64` or
`arm64`. Output goes to `target/appimage/<architecture>/dist/`.

The [builder](appimage/build-appimage.sh) reuses the Debian binary, SQLite and
license notices. It verifies pinned appimagetool and runtime downloads with
SHA-256. CI is configured to build native x86_64 and aarch64 images and check
`--version` without FUSE. This checks packaging and CLI execution; server health,
compute and AWS behavior need separate tests.
See [AppImage requirements and usage](../docs/SETUP.md#appimage-without-installation).

Local validation used an x86_64 fixture package. Full server images on both
architectures still need a successful CI run before publication.

### Publish a release

1. Commit and push the version and Cargo.lock changes.
2. Complete the [local release checks](#local-release-checks), the security audit
   required by `AGENTS.md`, and the VM/WSL checks. Wait for CI to pass.
3. Derive the tag from Cargo.toml and push it:

   ```sh
   bash scripts/check-package-version.sh
   release_tag="$(bash scripts/package-version.sh tag)"
   bash scripts/check-release-version.sh "$release_tag"
   git tag -a "$release_tag" -m "LocallyCloud $release_tag"
   git push origin "$release_tag"
   ```

The tag run publishes after all checks pass. Alpha/beta/rc tags become prereleases
and keep the existing `latest`; tags without a suffix become normal releases.
Prerelease downloads use `/releases` or the specific tag, not `/releases/latest`.

Release assets include `.deb`, `.pkg.tar.zst`, both `.AppImage` architectures,
ExtendDB workers and notices, `components.json`, Rust SBOMs, `SHA256SUMS` and
`provenance.sigstore.json`. The workflow uses `GITHUB_TOKEN`; only the publishing
job has write access. No personal token or additional secrets are needed.
Actions must be enabled. APT and AUR publication remain separate steps.

If a tag fails version validation, fix Cargo.toml and Cargo.lock in a new release
commit and use a matching, unused tag. Rerunning the old tag uses the old commit.
Preserve published tags and packages. Publication refuses to replace an existing release.

### Repair the first beta checksum manifest

The first beta's checksum manifest used `~` where GitHub published `.`. Run
**Repair release checksums** with tag `v0.1.0-beta.1` to verify the assets and
replace only `SHA256SUMS`. Keep the tag and packages unchanged.

The [repair workflow](../.github/workflows/release-checksums.yml) must be on the
repository's default branch to appear in Actions; see [manual workflow instructions](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).

Documentation: [official checkout action](https://github.com/actions/checkout), [artifacts](https://github.com/actions/upload-artifact), [creating releases with GitHub CLI](https://cli.github.com/manual/gh_release_create).
