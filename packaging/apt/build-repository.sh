#!/usr/bin/env bash
set -euo pipefail

fail() { printf '%s\n' "$*" >&2; exit 1; }

[[ $# == 4 || $# == 5 ]] || fail 'Usage: build-repository.sh SIGNING_FINGERPRINT OUTPUT_DIR AMD64.deb ARM64.deb [PASSPHRASE_FILE]'
signing_key=$1
output=$2
signing_options=()
if [[ $# == 5 ]]; then
    [[ -f $5 && -r $5 ]] || fail 'Passphrase file must be a readable regular file.'
    signing_options=(--pinentry-mode loopback --passphrase-file "$(realpath -- "$5")")
fi
[[ $signing_key =~ ^([[:xdigit:]]{40}|[[:xdigit:]]{64})$ ]] || fail 'Use the full signing-key fingerprint.'
[[ ! -e $output && ! -L $output ]] || fail 'Output must not exist; publish the completed directory separately.'
for tool in dpkg-deb dpkg-scanpackages apt-ftparchive gpg gzip; do
    command -v "$tool" >/dev/null || fail "Required tool missing: $tool"
done

packages=()
inputs=("$3" "$4")
architectures=(amd64 arm64)
version=''
for index in 0 1; do
    input=${inputs[$index]}
    architecture=${architectures[$index]}
    [[ -f $input ]] || fail "Package not found: $input"
    [[ $(dpkg-deb --field "$input" Package) == locallycloud ]] || fail "Unexpected package: $input"
    [[ $(dpkg-deb --field "$input" Architecture) == "$architecture" ]] || fail "Expected $architecture package: $input"
    package_version=$(dpkg-deb --field "$input" Version)
    [[ $package_version =~ ^[[:alnum:]~.+:-]+$ ]] || fail 'Unsafe Debian version.'
    [[ -z $version || $package_version == "$version" ]] || fail 'Both architectures must have the same version.'
    version=$package_version
    packages+=("$(realpath -- "$input")")
done

output=$(realpath -m -- "$output")
mkdir -p -- "$(dirname -- "$output")"
staging=$(mktemp -d "$(dirname -- "$output")/.apt-repository.XXXXXX")
trap 'rm -rf -- "$staging"' EXIT
chmod 755 "$staging"
cd "$staging"
mkdir -p pool/main/l/locallycloud
for index in 0 1; do
    cp -- "${packages[$index]}" "pool/main/l/locallycloud/locallycloud_${version}_${architectures[$index]}.deb"
done

for architecture in amd64 arm64; do
    directory="dists/beta/main/binary-$architecture"
    mkdir -p "$directory"
    dpkg-scanpackages --arch "$architecture" pool /dev/null > "$directory/Packages"
    gzip -n -9 -c "$directory/Packages" > "$directory/Packages.gz"
done
apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=LocallyCloud \
    -o APT::FTPArchive::Release::Label=LocallyCloud \
    -o APT::FTPArchive::Release::Suite=beta \
    -o APT::FTPArchive::Release::Codename=beta \
    -o 'APT::FTPArchive::Release::Architectures=amd64 arm64' \
    -o APT::FTPArchive::Release::Components=main \
    -o APT::FTPArchive::Release::Description='LocallyCloud beta packages' \
    -o APT::FTPArchive::Release::NotAutomatic=yes \
    -o APT::FTPArchive::Release::ButAutomaticUpgrades=yes \
    release dists/beta > dists/beta/Release
gpg --batch "${signing_options[@]}" --local-user "$signing_key" --digest-algo SHA256 \
    --clearsign --output dists/beta/InRelease dists/beta/Release
gpg --batch "${signing_options[@]}" --local-user "$signing_key" --digest-algo SHA256 \
    --detach-sign --output dists/beta/Release.gpg dists/beta/Release
gpg --batch --export-options export-minimal --export "$signing_key" > locallycloud-archive-keyring.gpg
[[ -s locallycloud-archive-keyring.gpg ]] || fail 'Public signing key export is empty.'
gpg --batch --verify dists/beta/Release.gpg dists/beta/Release
chmod -R a+rX .
cd /
mv -T -- "$staging" "$output"
printf 'Signed beta repository: %s\n' "$output"
