#!/bin/sh
# Renders app-icon.svg into the icons the desktop embeds:
#   app-icon.png      1024 px, the macOS Dock icon (keeps Apple's margin)
#   app-icon-256.png  the tile alone, the X11 window icon
#   app-icon.ico      the tile alone at 16-256 px, the Windows exe icon
# Needs resvg (cargo install resvg) and Python with Pillow.
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
resvg --width 1024 --height 1024 app-icon.svg app-icon.png
sed 's/viewBox="0 0 1024 1024"/viewBox="100 100 824 824"/' app-icon.svg >"$tmp/tile.svg"
resvg --width 256 --height 256 "$tmp/tile.svg" app-icon-256.png
for size in 16 24 32 48 64 128; do
  resvg --width "$size" --height "$size" "$tmp/tile.svg" "$tmp/$size.png"
done
python3 - "$tmp" <<'PY'
import sys
from PIL import Image
tmp = sys.argv[1]
sizes = [16, 24, 32, 48, 64, 128]
images = [Image.open(f"{tmp}/{s}.png") for s in sizes]
large = Image.open("app-icon-256.png")
# Each size is rendered from the SVG, not downscaled, so small icons stay crisp.
large.save("app-icon.ico", format="ICO", sizes=[(s, s) for s in sizes + [256]],
           append_images=images)
PY
