#!/usr/bin/env bash
# Rebuild PNG exports from the checked-in SVGs. Requires librsvg (rsvg-convert).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
for size in 16 24 32 48 64 128 256 512; do
  rsvg-convert -w "$size" -h "$size" locallycloud.svg -o "locallycloud-$size.png"
done
rsvg-convert -w 512 -h 512 locallycloud.svg -o locallycloud-logo.png
rsvg-convert -w 512 locallycloud-symbol.svg -o locallycloud-symbol.png
rsvg-convert -w 512 locallycloud-symbol-light.svg -o locallycloud-symbol-light.png
rsvg-convert -w 1200 locallycloud-wordmark.svg -o locallycloud-wordmark.png
rsvg-convert -w 1200 locallycloud-wordmark-light.svg -o locallycloud-wordmark-light.png
rsvg-convert locallycloud-social.svg -o locallycloud-social.png

# Compatibility filenames used by the current Debian and Arch packaging.
for asset in locallycloud*.svg locallycloud*.png; do
  cp -- "$asset" "${asset/locallycloud/localcloud}"
done
