#!/usr/bin/env bash
set -euo pipefail

[[ $# == 0 || $# == 2 ]] || { printf 'Usage: check-repository.sh [AMD64.deb ARM64.deb]\n' >&2; exit 1; }
builder=$(realpath -- "$(dirname -- "${BASH_SOURCE[0]}")/build-repository.sh")
for tool in dpkg-deb dpkg-scanpackages apt-ftparchive apt-get apt-cache gpg gpgconf; do
    command -v "$tool" >/dev/null || { printf 'Required tool missing: %s\n' "$tool" >&2; exit 1; }
done
temporary=$(mktemp -d)
trap 'gpgconf --homedir "$GNUPGHOME" --kill gpg-agent >/dev/null 2>&1 || true; rm -rf -- "$temporary"' EXIT
export GNUPGHOME="$temporary/gnupg"
mkdir -m 700 "$GNUPGHOME"
passphrase_file="$GNUPGHOME/passphrase"
printf 'Disposable APT signing fixture\n' > "$passphrase_file"
chmod 600 "$passphrase_file"
gpg --batch --pinentry-mode loopback --passphrase-file "$passphrase_file" \
    --quick-generate-key 'APT fixture <apt-test@example.invalid>' ed25519 sign 1d
fingerprint=$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" { print $10; exit }')
version=0.1.0~beta.1-1
if [[ $# == 2 ]]; then
    cp -- "$1" "$temporary/amd64.deb"
    cp -- "$2" "$temporary/arm64.deb"
    version=$(dpkg-deb --field "$temporary/amd64.deb" Version)
else
    for architecture in amd64 arm64; do
        mkdir -p "$temporary/$architecture/DEBIAN"
        cat > "$temporary/$architecture/DEBIAN/control" <<EOF
Package: locallycloud
Version: $version
Architecture: $architecture
Maintainer: APT fixture <apt-test@example.invalid>
Description: Signed repository verification fixture
EOF
        dpkg-deb --build --root-owner-group "$temporary/$architecture" "$temporary/$architecture.deb"
    done
fi
if bash "$builder" "$fingerprint" "$temporary/rejected" "$temporary/arm64.deb" "$temporary/amd64.deb"; then
    printf 'Unexpectedly accepted reversed architectures.\n' >&2
    exit 1
fi
[[ ! -e $temporary/rejected ]]
gpgconf --homedir "$GNUPGHOME" --kill gpg-agent
bash "$builder" "$fingerprint" "$temporary/repository" "$temporary/amd64.deb" "$temporary/arm64.deb" "$passphrase_file"
mkdir -p "$temporary/apt/lists/partial" "$temporary/apt/cache/archives/partial" "$temporary/apt/empty"
touch "$temporary/apt/status"
export APT_CONFIG="$temporary/apt/apt.conf"
printf 'Dir::Etc::main "/dev/null";\nDir::Etc::parts "%s";\n' \
    "$temporary/apt/empty" > "$APT_CONFIG"
printf 'deb [arch=amd64,arm64 signed-by=%s] file:%s beta main\n' \
    "$temporary/repository/locallycloud-archive-keyring.gpg" "$temporary/repository" > "$temporary/apt/sources.list"
options=(
    -o "Dir::Etc::sourcelist=$temporary/apt/sources.list"
    -o "Dir::Etc::sourceparts=$temporary/apt/empty"
    -o "Dir::Etc::trusted=$temporary/apt/absent.gpg"
    -o "Dir::Etc::trustedparts=$temporary/apt/empty"
    -o "Dir::State=$temporary/apt"
    -o "Dir::State::status=$temporary/apt/status"
    -o "Dir::Cache=$temporary/apt/cache"
    -o "APT::Sandbox::User=$(id -un)"
    -o APT::Architectures::=amd64 -o APT::Architectures::=arm64
    -o APT::Update::Error-Mode=any
)
apt-get "${options[@]}" update
for architecture in amd64 arm64; do
    apt-cache "${options[@]}" show "locallycloud:$architecture" | grep -Fx "Version: $version"
done
mkdir "$temporary/downloads"
cd "$temporary/downloads"
apt-get "${options[@]}" download "locallycloud:amd64=$version" "locallycloud:arm64=$version"
for package in *.deb; do
    architecture=$(dpkg-deb --field "$package" Architecture)
    cmp -- "$package" "$temporary/$architecture.deb"
done
sed -i 's/Description: LocallyCloud beta packages/Description: Tampered repository/' \
    "$temporary/repository/dists/beta/InRelease"
if apt-get "${options[@]}" update; then
    printf 'Unexpectedly accepted a tampered InRelease.\n' >&2
    exit 1
fi
printf 'Signed metadata, both architectures, Debian version, downloads and tamper rejection: OK\n'
