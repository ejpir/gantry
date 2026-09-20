# Landing-page recordings

`index3.html` uses:

- `gantry-tui-v3.png` — still preview, shown by default.
- `gantry-tui-v3.gif` — 24-second, 1137 × 672 recording at 5 fps. Loaded only
  when the visitor chooses **Play demo**. **Stop demo** restores the still.

The v3 recording was captured from the real TUI built from `a812c02`, on Linux
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
- Go, Node.js/npm, Python 3, ffmpeg, Chrome/Chromium, and DejaVu Sans Mono.
- The matching `gantry-kernel-*`, `nerdbox-rootfs-*.erofs`, and
  `gantry-default-image-*.erofs` staged in `artifacts/`.
- Network access for the capture dependencies and the sample HTTP requests.

The script builds the current host and guest binaries, installs pinned
Playwright/xterm.js packages **outside the repository**, and renders the real
PTY output in headless Chrome. No TUI-specific test hooks or fabricated state
are used. It isolates `HOME`, `GANTRY_HOME` and guest assets in a temporary
workspace, stops the demo VMs, and removes the temporary files on completion.
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
terminal dimensions or recording length, update the image dimensions and play
button label in `index3.html` as well.

The original `gantry-tui.gif` and earlier landing pages are intentionally
unchanged.
