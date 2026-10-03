# LocallyCloud brand assets

A cloud with a terminal, in dark green, cream, and lavender. The SVG files are the source for exports; the name is converted to paths so it does not depend on installed fonts.

| File | Usage |
| --- | --- |
| `locallycloud.svg` | Scalable square icon for applications and Linux packages. |
| `locallycloud-{16,24,32,48,64,128,256,512}.png` | Raster icons for application menus and tools that require PNG. |
| `locallycloud-logo.png` | 512 px square icon for the project avatar and releases. |
| `locallycloud-symbol.svg` / `.png` | Transparent symbol for light surfaces. |
| `locallycloud-symbol-light.svg` / `.png` | Transparent cream symbol for dark surfaces. |
| `locallycloud-wordmark.svg` / `.png` | Horizontal symbol and name for documentation and light headers. |
| `locallycloud-wordmark-light.svg` / `.png` | Horizontal version for dark surfaces. |
| `locallycloud-social.svg` / `.png` | 1280 × 640 px preview card for sharing the project. |

The Debian and Arch packages install the SVG and PNG sizes in `hicolor`. The `locallycloud.desktop` file retains `Icon=locallycloud`. The 512 px PNG is also available for a future portable package.

## Export

From the product root, with `rsvg-convert` installed:

```sh
bash packaging/assets/export-logos.sh
```

The symbols and horizontal versions have transparency. The application icon and social card have an intentional background. The name's typography is derived from Geist; its license is in `Geist-OFL.txt`.

The Debian and Arch scripts use the `locallycloud-*` assets directly. `export-logos.sh` regenerates only these versions. The launcher opens the product's current endpoint, `/_locallycloud/ui`.
