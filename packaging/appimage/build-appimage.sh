#!/usr/bin/env bash
# Repackage the tested Debian binary; do not compile a second server.
set -euo pipefail
umask 022
[[ $# == 1 ]] || { echo 'Usage: build-appimage.sh PACKAGE.deb' >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACKAGE="$(realpath "$1")"
VERSION="$(bash "$ROOT/scripts/package-version.sh" product)"
[[ "$(dpkg-deb -f "$PACKAGE" Package)" == locallycloud ]]
[[ "$(dpkg-deb -f "$PACKAGE" Version)" == "$(bash "$ROOT/scripts/package-version.sh" debian)" ]]
case "$(dpkg-deb -f "$PACKAGE" Architecture):$(uname -m)" in
  amd64:x86_64)
    ARCH=x86_64
    TOOL_SHA256=ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0
    RUNTIME_SHA256=2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d
    ;;
  arm64:aarch64)
    ARCH=aarch64
    TOOL_SHA256=f0837e7448a0c1e4e650a93bb3e85802546e60654ef287576f46c71c126a9158
    RUNTIME_SHA256=00cbdfcf917cc6c0ff6d3347d59e0ca1f7f45a6df1a428a0d6d8a78664d87444
    ;;
  *) echo 'Build AppImages natively from a matching amd64 or arm64 Debian package.' >&2; exit 1 ;;
esac
BUILD="$ROOT/target/appimage/$ARCH"
mkdir -p "$BUILD/tools" "$BUILD/dist"
download() {
  local url="$1" output="$2" checksum="$3"
  if [[ ! -f "$output" ]]; then
    curl --fail --show-error --silent --location "$url" -o "$output"
  fi
  printf '%s  %s\n' "$checksum" "$output" | sha256sum --check -
}
download "https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-$ARCH.AppImage" "$BUILD/tools/appimagetool" "$TOOL_SHA256"
download "https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-$ARCH" "$BUILD/tools/runtime" "$RUNTIME_SHA256"
chmod u+x "$BUILD/tools/appimagetool"
APPDIR="$BUILD/LocallyCloud.AppDir"
rm -rf -- "$APPDIR"
mkdir -p "$APPDIR"
dpkg-deb --extract "$PACKAGE" "$APPDIR"
install -Dm755 "$ROOT/packaging/appimage/AppRun" "$APPDIR/AppRun"
install -Dm644 "$ROOT/packaging/assets/locallycloud.svg" "$APPDIR/locallycloud.svg"
install -Dm644 "$ROOT/packaging/appimage/RUNTIME-LICENSE.txt" "$APPDIR/usr/share/doc/locallycloud/APPIMAGE_RUNTIME_LICENSE.txt"
cat > "$APPDIR/locallycloud.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=LocallyCloud
Comment=Run the local AWS service emulator
Exec=locallycloud
Icon=locallycloud
Terminal=true
Categories=Development;
DESKTOP
# Supply a verified runtime explicitly: appimagetool must not download one itself.
export ARCH
"$BUILD/tools/appimagetool" --appimage-extract-and-run \
  --runtime-file "$BUILD/tools/runtime" "$APPDIR" "$BUILD/dist/locallycloud-$VERSION-$ARCH.AppImage"
