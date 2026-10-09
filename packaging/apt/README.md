# Signed APT beta repository

The `.deb` assets in GitHub Releases can already be installed with
`apt install ./file.deb`. A repository also needs signed indexes and HTTPS
hosting. This directory prepares those files; it does not publish them or
generate a production signing key.

## Build a snapshot

Use Debian 13 or Ubuntu in a disposable VM or a CI runner with `dpkg-dev`,
`apt-utils`, and `gnupg`. These are repository maintenance tools, not dependencies
of the emulator. Nothing needs to be installed on the developer's host.

Download the amd64 and arm64 assets for the same release and verify them against
the corrected `SHA256SUMS`. Import the maintainer-controlled signing key into a
private `GNUPGHOME`, then run:

```bash
bash packaging/apt/build-repository.sh \
  FULL_SIGNING_KEY_FINGERPRINT \
  target/apt-repository \
  /path/to/locallycloud_amd64.deb \
  /path/to/locallycloud_arm64.deb
```

For a passphrase-protected key in noninteractive CI, append a fifth argument
pointing to a readable passphrase file provisioned with mode `0600` in a private
temporary directory. The script resolves that file before staging and supplies
it to GPG through `--pinentry-mode loopback --passphrase-file`; it never reads or
prints the secret into the command line. Without the fifth argument, GPG uses
its normal agent and pinentry behavior.

The output directory must not exist. The script validates the package name,
architecture order, and matching internal versions before creating a staged
snapshot. It renames the files using their Debian control metadata, preserving
`0.1.0~beta.1-1` even when a download filename has replaced `~` with `.`.

The resulting tree contains:

```text
locallycloud-archive-keyring.gpg
pool/main/l/locallycloud/*.deb
dists/beta/InRelease
dists/beta/Release
dists/beta/Release.gpg
dists/beta/main/binary-amd64/Packages{,.gz}
dists/beta/main/binary-arm64/Packages{,.gz}
```

`Packages` binds each package's path, size, and hashes. `Release` binds the
indexes; `InRelease` and `Release.gpg` authenticate that metadata. The exported
public key can verify the repository and contains no private signing material.
The `beta` suite is marked `NotAutomatic` with `ButAutomaticUpgrades`, so users
explicitly opt into installation and can subsequently receive its updates.
Each invocation builds one release snapshot containing both architectures.

## Verify in QEMU

On a disposable Debian/Ubuntu guest with the maintenance tools, run:

```bash
bash packaging/apt/check-repository.sh

# Verify the real release pair using the same isolated APT checks:
bash packaging/apt/check-repository.sh /path/to/amd64.deb /path/to/arm64.deb
```

This creates an ephemeral GPG home with a protected signing key and two small
fixture packages, stops only that home's agent to clear its passphrase cache,
runs the real builder with the passphrase file,
and invokes APT with isolated configuration, sources, trust, state, and cache paths.
It checks both architecture indexes, the Debian prerelease version, verified
downloads, rejection of reversed architecture inputs, and rejection of altered
signed metadata. It installs no package, modifies no system sources, and removes
the fixture files and agent when finished. Passing the real release pair checks
its exact versions and bytes with the same temporary signing identity; it does
not create a production signing key or leave a repository to publish.

## Publish

Before publication, choose an HTTPS base URL and a repository signing identity.
Upload the complete tree using an atomic static-site deployment, and retain old
package files while clients may still reference them. Serve binary files
unchanged and allow downloads of `.deb`, `.gpg`, `Packages`, `Packages.gz`, and
`InRelease`. A GitHub Release asset page is not an APT repository URL.

For CI signing, provision the private key and its passphrase through protected
secrets, plus the full signing fingerprint as configuration. Import only inside
a temporary private GPG home and remove it after signing. Keep the production
key outside the repository; the verification script's disposable key must never
be used for publishing. Hosting additionally needs its deployment credentials
or the provider's supported short-lived identity. These are operator choices;
no hosting or secret configuration is performed by the builder.

## Client installation after publication

Replace the example URL and fingerprint with the published values. Confirm the
key fingerprint against the maintainer's independently published fingerprint
before trusting it:

```bash
repository_url=https://YOUR_HOST/apt
curl --fail --location "$repository_url/locallycloud-archive-keyring.gpg" \
  --output locallycloud-archive-keyring.gpg
gpg --show-keys --with-fingerprint locallycloud-archive-keyring.gpg
sudo install -m 0644 locallycloud-archive-keyring.gpg /usr/share/keyrings/locallycloud-archive-keyring.gpg
printf 'deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/locallycloud-archive-keyring.gpg] %s beta main\n' \
  "$repository_url" | sudo tee /etc/apt/sources.list.d/locallycloud.list
sudo apt update
sudo apt install locallycloud
```

Package administration requires root; the emulator runs as the regular user.
The supported Debian/Ubuntu versions and optional compute tools remain those
in [PLATFORMS.md](../../docs/PLATFORMS.md).

The format and signature flow follow Debian's
[dpkg-scanpackages](https://manpages.debian.org/trixie/dpkg-dev/dpkg-scanpackages.1.en.html),
[apt-ftparchive](https://manpages.debian.org/trixie/apt-utils/apt-ftparchive.1.en.html),
and [apt-secure](https://manpages.debian.org/trixie/apt/apt-secure.8.en.html)
documentation.
