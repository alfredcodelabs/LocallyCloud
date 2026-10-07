# Versioning and packages

The product version is chosen manually in `[workspace.package].version` in `Cargo.toml`. All workspace crates inherit that version. Debian and the Arch checkout package derive it automatically using `scripts/package-version.sh`.

We use three components, `MAJOR.MINOR.PATCH`, with no leading zeros. Prerelease channels use `-alpha.N`, `-beta.N`, or `-rc.N`, with N starting at 1. The `v` prefix is used only for Git tags.

| Release | Cargo | Git tag | Debian, revision 1 | Arch, pkgrel 1 |
| --- | --- | --- | --- | --- |
| First beta | `0.1.0-beta.1` | `v0.1.0-beta.1` | `0.1.0~beta.1-1` | `0.1.0beta.1-1` |
| Second beta | `0.1.0-beta.2` | `v0.1.0-beta.2` | `0.1.0~beta.2-1` | `0.1.0beta.2-1` |
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

For a new version, edit Cargo.toml and update Cargo.lock with `cargo update --workspace --offline`. Run the checks before creating the tag. GitHub Actions requires the tag to match the output of `package-version.sh tag` and builds all artifacts from that commit. The local scripts do not publish releases or packages.

## Packaging revisions

If you fix only the package for an already published version, increment its revision: `pkgrel` for Arch and `LOCALLYCLOUD_DEBIAN_REVISION` for Debian. These revisions can evolve independently. Reset both to 1 for each new product version.

```sh
# Debian, revision 2 of the same product version:
LOCALLYCLOUD_DEBIAN_REVISION=2 bash packaging/debian/build-deb.sh /path/to/sqlite-autoconf-3530400.tar.gz
```

Keep revision 1 before the first publication.

## AUR

There are two Arch recipes. `packaging/arch/PKGBUILD` builds the local checkout and is what CI uses. `packaging/aur/PKGBUILD` is the AUR recipe: it downloads the release tag's source archive from GitHub, verifies its SHA-256, fetches crates in `prepare()` with `cargo fetch --locked`, builds offline with `--frozen`, runs the core library tests in `check()`, and installs the binary, license notices, man page, launcher, and icons.

After the release tag is published, on an Arch machine:

```sh
bash packaging/aur/update.sh            # tag derived from Cargo.toml, or pass one: v0.1.0-beta.1
cd packaging/aur && makepkg --cleanbuild && namcap PKGBUILD ./*.pkg.tar.zst
```

`update.sh` sets `pkgver`, `_tag`, `pkgrel=1`, and `sha256sums` from the published archive and regenerates `.SRCINFO`. Copy `PKGBUILD` and `.SRCINFO` into the AUR Git repository (`ssh://aur@aur.archlinux.org/locallycloud.git`) and push them; the AUR account and its SSH key are configured separately from GitHub. For a packaging-only fix of the same release, increment `pkgrel` in both recipes and regenerate `.SRCINFO` with `makepkg --printsrcinfo > .SRCINFO`.

References: [SemVer](https://semver.org/), [Debian](https://www.debian.org/doc/debian-policy/ch-controlfields.html#version), [Arch](https://man.archlinux.org/man/PKGBUILD.5.en).

## GitHub Actions

The `.github/workflows/packages.yml` workflow runs on pull requests, pushes to `main`, `master`, `develop`, and `stage`, and `v*` tags. It can also be run manually to check a branch without publishing.

It validates version formats, tag matching, and the versions of all crates. It checks `cargo fmt`, builds and installs both packages, and runs library tests for `locallycloud-core` and `locallycloud-state`. It does not yet cover all service integrations, PostgreSQL, or OCI runtimes.

Debian is built natively on Debian 13 for `amd64` and `arm64` (GitHub `ubuntu-24.04` and `ubuntu-24.04-arm` runners) using the Rust version declared in Cargo.toml. SQLite 3.53.4 is downloaded from the official site, verified against the SHA-256 in the packaging script, and linked statically. The `libc6` dependency is computed from the binary and must not exceed glibc 2.39, the oldest supported LTS. A follow-up job installs each `.deb` with `apt` on Debian 13, Ubuntu 24.04, and Ubuntu 26.04 and starts the server; releases wait for it. Arch is built in its rolling x86_64 environment using Rust and SQLite from its repositories; the PKGBUILD also declares `aarch64` for Arch Linux ARM, which CI does not build yet.

After saving and pushing the version and Cargo.lock changes:

```sh
bash scripts/check-package-version.sh
git tag -a v0.1.0-beta.1 -m "LocallyCloud 0.1.0-beta.1"
git push origin v0.1.0-beta.1
```

Pushing the tag automatically publishes to GitHub Releases after both builds and the checks pass. Alpha/beta/rc tags are marked as prereleases and do not replace `latest`; tags without a suffix publish a normal release. The release includes `.deb`, `.pkg.tar.zst`, and `SHA256SUMS`. The first beta will not appear at `/releases/latest`: the website should link to `/releases` or the specific tag.

No personal token or additional secrets are required: the workflow uses `GITHUB_TOKEN`, with write access only in the publishing job. Actions must be enabled in the repository. The workflow does not publish an APT repository or submit the recipe to AUR; those channels need their own configuration.

If a build fails, fix the issue before publishing a new tag; do not move tags that already have a release. Rerunning a workflow with an already published release will fail when attempting to create it, preventing silent replacement of its packages.

Documentation: [official checkout action](https://github.com/actions/checkout), [artifacts](https://github.com/actions/upload-artifact), [creating releases with GitHub CLI](https://cli.github.com/manual/gh_release_create).
