#!/usr/bin/env bash
set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SQLITE_TARBALL="${1:?usage: build-deb.sh sqlite-autoconf-3530400.tar.gz}"
SQLITE_SHA256=0e9483900e92cd5de8fd48d16bf9200145a61f7fd5be542a5ac81d8a9516eb9c
BUILD_DIR="$ROOT/target/debian-package"
SQLITE_PREFIX="$BUILD_DIR/sqlite-3.53.4"
PACKAGE_VERSION="$(bash "$ROOT/scripts/package-version.sh" debian "${LOCALLYCLOUD_DEBIAN_REVISION:-1}")"

[[ "$(dpkg --print-architecture)" == amd64 ]] || { echo 'Debian amd64 required' >&2; exit 1; }
printf '%s  %s\n' "$SQLITE_SHA256" "$SQLITE_TARBALL" | sha256sum -c -

if [[ ! -f "$SQLITE_PREFIX/lib/libsqlite3.a" ]]; then
  mkdir -p "$BUILD_DIR/sqlite-source"
  tar -xzf "$SQLITE_TARBALL" --strip-components=1 -C "$BUILD_DIR/sqlite-source"
  (
    cd "$BUILD_DIR/sqlite-source"
    CFLAGS='-O2 -DSQLITE_ENABLE_COLUMN_METADATA -DSQLITE_DEFAULT_FOREIGN_KEYS=1' \
      ./configure --prefix="$SQLITE_PREFIX" --disable-shared --enable-static
    make -j"$(nproc)"
    make install
  )
fi

export SQLITE3_LIB_DIR="$SQLITE_PREFIX/lib"
export SQLITE3_INCLUDE_DIR="$SQLITE_PREFIX/include"
export SQLITE3_STATIC=1
cargo build --manifest-path "$ROOT/Cargo.toml" --release --locked -p localcloud
BIN="$ROOT/target/release/localcloud"
if readelf -d "$BIN" | grep -q 'libsqlite3'; then
  echo 'SQLite is still dynamically linked' >&2
  exit 1
fi

STAGE="$BUILD_DIR/stage"
rm -rf "$STAGE"
install -Dm755 "$BIN" "$STAGE/usr/bin/localcloud"
install -Dm644 "$ROOT/packaging/assets/locallycloud.desktop" "$STAGE/usr/share/applications/locallycloud.desktop"
install -Dm644 "$ROOT/packaging/assets/locallycloud.svg" "$STAGE/usr/share/icons/hicolor/scalable/apps/locallycloud.svg"
for size in 16 24 32 48 64 128 256 512; do
  install -Dm644 "$ROOT/packaging/assets/locallycloud-$size.png" "$STAGE/usr/share/icons/hicolor/${size}x${size}/apps/locallycloud.png"
done
mkdir -p "$STAGE/usr/share/doc/localcloud" "$STAGE/DEBIAN"
{
  printf 'Copyright 2026 Alfred Rodriguez G\nLicense: Apache-2.0\n\n'
  cat "$ROOT/LICENSE.md"
} > "$STAGE/usr/share/doc/localcloud/copyright"
cat > "$STAGE/DEBIAN/control" <<CONTROL
Package: localcloud
Version: $PACKAGE_VERSION
Section: devel
Priority: optional
Architecture: amd64
Maintainer: Alfred Rodriguez G <alfredcode.dev@gmail.com>
Depends: libc6 (>= 2.41), libgcc-s1
Suggests: crun, postgresql, xdg-utils
Description: Local AWS service emulator
 LocalCloud runs AWS-compatible development services on one local endpoint.
CONTROL
mkdir -p "$BUILD_DIR/dist"
dpkg-deb --build --root-owner-group "$STAGE" "$BUILD_DIR/dist/localcloud_${PACKAGE_VERSION}_amd64.deb"
