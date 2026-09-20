# Landing-page recordings

`index3.html` uses:

- `gantry-tui-v3.png` — native 2× still preview, shown by default.
- `gantry-tui-v3.webm` — lossless RGB VP9, preferred for inline playback. No
  palette reduction or chroma subsampling, so colored text stays sharp.
- `gantry-tui-v3.mp4` — high-quality H.264 fallback and direct video link.
- `gantry-tui-v3.gif` — downloadable 256-color GIF, without dithering speckle.

All media is **2274 × 1344**, captured at native 2× pixel density rather than
upscaled from the previous recording. Animations run for **24 seconds at
10 fps**. The video does not autoplay and uses `preload="none"`; playback is
user-initiated. Native controls provide pause, seeking, and fullscreen, even
without JavaScript. The page also links to the GIF separately.

The HD v3 recording was captured from the real TUI built from `a382dd6`, on Linux
x86-64/KVM. It shows Overview → Sandboxes → Edit Sandbox → Traffic → Network
rules → Mounts → MCP → Overview. The short loading transitions between views
are omitted; the UI and displayed data are not mocked.

Two disposable Alpine VMs provide sample data:

- `workspace`: 2 vCPUs, 1 GiB RAM, SSH and a writable sample project share.
- `agent`: 1 vCPU, 512 MiB RAM, a read-only project share, a filesystem MCP
  gateway, and a default-deny egress policy with a domain allowlist.

HTTP requests to example.com and the Alpine package mirror produce real
traffic counters and policy denials. The recording demonstrates the interface,
not benchmark performance or a hardened security boundary. It contains no
personal workspaces, credentials or remote-manager connections.

## Record again

From the repository root:

```sh
node scripts/record-tui-demo.mjs
```

Prerequisites:

- Linux x86-64 or ARM64 with read/write access to `/dev/kvm`.
- Go, Node.js/npm, Python 3, ffmpeg with libvpx-vp9 and libx264,
  Chrome/Chromium, and DejaVu Sans Mono.
- The matching `gantry-kernel-*`, `nerdbox-rootfs-*.erofs`, and
  `gantry-default-image-*.erofs` staged in `artifacts/`.
- Network access for the capture dependencies and the sample HTTP requests.

The script builds the current host and guest binaries, installs pinned
Playwright/xterm.js packages **outside the repository**, and renders the real
PTY output in headless Chrome at `deviceScaleFactor: 2`. Full-resolution PNG
frames are encoded independently as lossless RGB VP9, H.264 (CRF 14), and a
256-color GIF. No TUI-specific test hooks or fabricated state are used. It
isolates `HOME`, `GANTRY_HOME` and guest assets in a temporary workspace, stops
the demo VMs, and removes the temporary files on completion.
It does not alter your normal Gantry configuration or sandboxes.

Override tool paths or write a separate recording:

```sh
node scripts/record-tui-demo.mjs \
  --chrome /usr/bin/chromium \
  --font /usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf \
  --assets /path/to/staged-assets \
  --output /tmp/gantry-demo
```

Use `--keep` to retain frames and isolated state for debugging. If you change
terminal dimensions or recording length, update the video dimensions and play
button label in `index3.html` as well.

The original `gantry-tui.gif` and earlier landing pages are intentionally
unchanged.
