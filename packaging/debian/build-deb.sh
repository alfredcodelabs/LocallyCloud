#!/usr/bin/env bash
set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SQLITE_TARBALL="${1:?usage: build-deb.sh sqlite-autoconf-3530400.tar.gz}"
SQLITE_SHA256=0e9483900e92cd5de8fd48d16bf9200145a61f7fd5be542a5ac81d8a9516eb9c
BUILD_DIR="$ROOT/target/debian-package"
DEB_ARCH="$(dpkg --print-architecture)"
case "$DEB_ARCH" in
  amd64|arm64) ;;
  *) echo "Unsupported architecture $DEB_ARCH; amd64 or arm64 required" >&2; exit 1 ;;
esac
SQLITE_PREFIX="$BUILD_DIR/sqlite-3.53.4-$DEB_ARCH"
PACKAGE_VERSION="$(bash "$ROOT/scripts/package-version.sh" debian "${LOCALLYCLOUD_DEBIAN_REVISION:-1}")"

printf '%s  %s\n' "$SQLITE_SHA256" "$SQLITE_TARBALL" | sha256sum -c -

if [[ ! -f "$SQLITE_PREFIX/lib/libsqlite3.a" ]]; then
  rm -rf "$BUILD_DIR/sqlite-source-$DEB_ARCH"
  mkdir -p "$BUILD_DIR/sqlite-source-$DEB_ARCH"
  tar -xzf "$SQLITE_TARBALL" --strip-components=1 -C "$BUILD_DIR/sqlite-source-$DEB_ARCH"
  (
    cd "$BUILD_DIR/sqlite-source-$DEB_ARCH"
    CFLAGS='-O2 -DSQLITE_ENABLE_COLUMN_METADATA -DSQLITE_DEFAULT_FOREIGN_KEYS=1' \
      ./configure --prefix="$SQLITE_PREFIX" --disable-shared --enable-static
    make -j"$(nproc)"
    make install
  )
fi

export SQLITE3_LIB_DIR="$SQLITE_PREFIX/lib"
export SQLITE3_INCLUDE_DIR="$SQLITE_PREFIX/include"
export SQLITE3_STATIC=1
cargo build --manifest-path "$ROOT/Cargo.toml" --release --locked -p locallycloud
BIN="$ROOT/target/release/locallycloud"
if readelf -d "$BIN" | grep -q 'libsqlite3'; then
  echo 'SQLite is still dynamically linked' >&2
  exit 1
fi

# The oldest supported LTS (Ubuntu 24.04, also common on WSL) ships glibc 2.39 on amd64 and arm64.
GLIBC_BASELINE="${LOCALLYCLOUD_GLIBC_BASELINE:-2.39}"
GLIBC_REQUIRED="$(objdump -T "$BIN" | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sed 's/GLIBC_//' | sort -V | tail -1)"
if [[ "$(printf '%s\n%s\n' "$GLIBC_REQUIRED" "$GLIBC_BASELINE" | sort -V | tail -1)" != "$GLIBC_BASELINE" ]]; then
  echo "Binary requires glibc $GLIBC_REQUIRED, above the supported baseline $GLIBC_BASELINE" >&2
  exit 1
fi

STAGE="$BUILD_DIR/stage-$DEB_ARCH"
DOC="$STAGE/usr/share/doc/locallycloud"
MAINTAINER='Alfred Rodriguez G <alfredcode.dev@gmail.com>'
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || date +%s)}"
export SOURCE_DATE_EPOCH
rm -rf "$STAGE"
install -Dm755 "$BIN" "$STAGE/usr/bin/locallycloud"
strip --strip-unneeded --remove-section=.comment --remove-section=.note "$STAGE/usr/bin/locallycloud"
install -Dm644 "$ROOT/packaging/assets/locallycloud.desktop" "$STAGE/usr/share/applications/locallycloud.desktop"
install -Dm644 "$ROOT/packaging/assets/locallycloud.svg" "$STAGE/usr/share/icons/hicolor/scalable/apps/locallycloud.svg"
for size in 16 24 32 48 64 128 256 512; do
  install -Dm644 "$ROOT/packaging/assets/locallycloud-$size.png" "$STAGE/usr/share/icons/hicolor/${size}x${size}/apps/locallycloud.png"
done
mkdir -p "$DOC" "$STAGE/DEBIAN" "$STAGE/usr/share/lintian/overrides" "$STAGE/usr/share/man/man1"
gzip -9n -c "$ROOT/packaging/assets/locallycloud.1" > "$STAGE/usr/share/man/man1/locallycloud.1.gz"

bash "$ROOT/scripts/third-party-licenses.sh" "$BUILD_DIR/THIRD_PARTY_LICENSES"
gzip -9n -c "$BUILD_DIR/THIRD_PARTY_LICENSES" > "$DOC/THIRD_PARTY_LICENSES.gz"
cat > "$DOC/copyright" <<COPYRIGHT
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: LocallyCloud
Upstream-Contact: $MAINTAINER
Source: https://github.com/alfredcodelabs/LocallyCloud
Comment: The locallycloud binary statically links third-party Rust crates and
 SQLite. Their licenses and copyright notices are reproduced in
 /usr/share/doc/locallycloud/THIRD_PARTY_LICENSES.gz.

Files: *
Copyright: 2026 Alfred Rodriguez G
License: Apache-2.0

License: Apache-2.0
 Licensed under the Apache License, Version 2.0 (the "License"); you may not
 use this file except in compliance with the License.
 .
 On Debian systems, the complete text of the Apache License, Version 2.0 can
 be found in "/usr/share/common-licenses/Apache-2.0".
COPYRIGHT
printf 'locallycloud (%s) unstable; urgency=medium\n\n  * Upstream release %s.\n\n -- %s  %s\n' \
  "$PACKAGE_VERSION" "$PACKAGE_VERSION" "$MAINTAINER" "$(date -u -R -d "@$SOURCE_DATE_EPOCH")" \
  | gzip -9n > "$DOC/changelog.Debian.gz"
cat > "$STAGE/usr/share/lintian/overrides/locallycloud" <<'OVERRIDES'
# unsafe-libyaml is a Rust translation of libyaml compiled into the binary, not a bundled C library.
locallycloud: embedded-library libyaml [usr/bin/locallycloud]
# The launcher opens the dashboard with xdg-open, from the recommended xdg-utils package.
locallycloud: desktop-command-not-in-package xdg-open [usr/share/applications/locallycloud.desktop]
# Distributed through upstream releases, not uploaded to the Debian archive with an ITP bug.
locallycloud: initial-upload-closes-no-bugs [usr/share/doc/locallycloud/changelog.Debian.gz:1]
OVERRIDES

cat > "$STAGE/DEBIAN/control" <<CONTROL
Package: locallycloud
Version: $PACKAGE_VERSION
Section: devel
Priority: optional
Architecture: $DEB_ARCH
Maintainer: $MAINTAINER
Installed-Size: $(du -sk --exclude=DEBIAN "$STAGE" | cut -f1)
Homepage: https://locallycloud.zentostudio.com
Depends: libc6 (>= $GLIBC_REQUIRED), libgcc-s1
Recommends: dbus-user-session, xdg-utils
Suggests: crun, postgresql
Description: Local AWS service emulator
 LocallyCloud emulates AWS services such as S3, DynamoDB, SQS, SNS, Lambda,
 API Gateway, EventBridge, Step Functions, and CloudFormation on one local
 endpoint, for developing and testing serverless applications with the AWS
 CLI, SDKs, Terraform, and SAM. It runs as a regular user without Docker.
 .
 Lambda, ECS, and EC2 execution use crun or youki; RDS uses PostgreSQL.
CONTROL
(cd "$STAGE" && find usr -type f -print0 | LC_ALL=C sort -z | xargs -0 md5sum) > "$STAGE/DEBIAN/md5sums"
mkdir -p "$BUILD_DIR/dist"
dpkg-deb --build --root-owner-group "$STAGE" "$BUILD_DIR/dist/locallycloud_${PACKAGE_VERSION}_${DEB_ARCH}.deb"
