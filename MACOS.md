# Running gantry on macOS (Apple Silicon)

## TL;DR

```sh
cd ~/repos/gantry
./run-macos.sh            # debug guest shell (our init + busybox)
./run-macos.sh rootfs     # real nerdbox rootfs + vminitd (RPC agent; no shell)
./run-macos.sh rootfs-shell # debug shell; nerdbox rootfs mounted at /mnt

# Proper nerdbox shell: run a container through vminitd/task.v3/crun.
# Terminal 1:
./hostctl-darwin-arm64 shell
# Terminal 2:
./run-macos.sh container
```

That's it. The script builds (if Go is installed) or uses the prebuilt
`gantry-darwin-arm64`, ad-hoc codesigns it with the hypervisor
entitlement, and runs it with the 16K-page kernel (`nerdbox-kernel-arm64`,
the exact kernel Docker ships for macOS sandboxes).

## Requirements

- Apple Silicon Mac, **macOS 13 (Ventura) or newer** — the vGIC is created
  with the `hv_gic_*` API added in macOS 13 (same as libsailor's
  hardware-GIC mode; `sw_vers` to check)
- The `com.apple.security.hypervisor` entitlement — handled by
  `run-macos.sh` via `codesign --sign - --entitlements entitlements.plist`

## What should happen

```
kernel: nerdbox-kernel-arm64 (...) @ 0x40200000, ... entry 0x40200000
initrd: initramfs-shell.cpio.gz (1864082 bytes) @ 0x46000000
fdt: NNNN bytes @ 0x40000000
booting guest under Hypervisor.framework
------------------------------------------------
[    0.000000] Linux version 7.0.12 ...
...
 gantry guest init (PID 1, static Go)
[init] starting busybox sh on /dev/console (type 'exit' to power off)
guest#
```

`exit` at the prompt → guest does PSCI `SYSTEM_OFF` → gantry exits.

## Interactive shell through nerdbox

`rootfs` deliberately has no shell: `/sbin/vminitd` is an RPC agent. The
architecturally correct shell is a container task:

1. `hostctl shell` accepts vminitd's ttrpc dial-back on port 1025.
2. `bundle.v1.Create` uploads `config.json`.
3. `task.v3.Create` mounts `/dev/vdb` (`shell-rootfs.erofs`) as the OCI rootfs.
4. `task.v3.Start` invokes the guest's `/sbin/crun`.
5. Separate host→guest vsock connections on port 1026 carry `stream://` stdin/stdout.
6. The launcher starts gvproxy and connects a two-queue virtio-net device to
   its Unix-datagram vfkit endpoint; vminitd obtains an address using DHCP.

The result is a networked `container#` prompt inside a real OCI container,
while vminitd remains PID 1 in the real nerdbox rootfs. Try `ip addr`,
`ping 192.168.127.1`, and `ping nu.nl`.

## Full Debian userland (sbx-kit style)

`debian-bookworm.erofs` is the official `debian:bookworm-slim` arm64 OCI
image flattened to EROFS by `mkimage.sh` (same role as an sbx "kit" image).
`rwlayer.ext4` is a 512 MiB ext4 image from `mkrwlayer.sh` with pre-created
`/upper` + `/work` — the sbx `rwlayer.img` equivalent.

```sh
# Terminal 1:
./hostctl-darwin-arm64 shell --rw -- /bin/bash
# Terminal 2:
IMAGE=debian-bookworm.erofs RWLAYER=rwlayer.ext4 ./run-macos.sh container
```

With `--rw`, the container root is overlayfs: EROFS `/dev/vdb` as read-only
lower + ext4 `/dev/vdc` as the writable upper (assembled by the guest's
`mountutil` with `{{mount N}}` templates, exactly like nerdbox). The result
is a writable Debian system: `apt update && apt install -y curl vim` works,
and changes persist in `rwlayer.ext4` across reboots. Omit `--rw` (and
`RWLAYER`) for a read-only root with tmpfs `/tmp`.

Guest time comes from the virtio-rtc device (spec device ID 17, same
protocol as libsailor's `crates/devices/virtio-rtc`): the kernel syncs at
probe (`hctosys`) and vminitd's clock service keeps it synced through the
driver's PTP clock. Without it the guest sits at epoch and apt reports
"Release file is not valid yet".

Rebuild the image for any OCI base (the sbx kit model) — `mkimage.sh`
needs docker + mkfs.erofs and must run on Linux (e.g. the dev container
with the repo shared to the Mac):

```sh
./mkimage.sh debian:bookworm-slim debian-bookworm.erofs   # how the shipped image was made
./mkimage.sh alpine:latest alpine.erofs                   # any linux/arm64 OCI image
./mkrwlayer.sh rwlayer-dev2.ext4 512                      # a new writable layer

# what mkimage.sh does: docker pull --platform linux/arm64 → docker create
# → docker export | tar -x → mkfs.erofs -b4096 → fsck.erofs verify
```

Then: `gantry start <name> -image alpine.erofs -rwlayer rwlayer-dev2.ext4`.

## Host directory sharing (virtio-fs, sbx-style)

Mirrors nerdbox/Docker bind mounts: a macOS directory is exported over a
virtio-fs device, mounted in the guest through vminitd's mount API, and
bind-mounted into the container by crun. No ext4 image involved.

```sh
# Terminal 1:
./hostctl-darwin-arm64 shell --share
# Terminal 2:
GANTRY_SHARE=/Users/you/somedir GANTRY_DEBUG_FS=1 ./run-macos.sh container
# Inside the container: /host is the macOS directory (live, read-write)

# Multiple shares, read-only support (TAG=PATH[,ro]):
GANTRY_SHARES="code=/Users/you/repos,ro docs=/Users/you/Documents" \
  ./run-macos.sh container
# Inside the container: /host/code (read-only), /host/docs (read-write)
# (with several shares, even GANTRY_SHARE's hostshare lands at /host/hostshare)
```

`hostctl --share` discovers the exports from `shares.json`, which gantry
writes next to the vsock sockets — no duplicate configuration. `ro` is
enforced the same way Docker enforces it: the guest mounts the tag with
`MS_RDONLY` and the OCI bind gets the `ro` option, so the guest kernel VFS
rejects writes before they reach the FUSE server.

Under the hood: `-share TAG=PATH[,ro]` (repeatable) adds a virtio-fs MMIO device whose FUSE
requests are served by an embedded go-fuse loopback of the host directory
(vendored under `third_party/go-fuse` with Linux-wire structures and errno
mapping, since the guest is Linux while the host is macOS). `hostctl
--share` calls the guest mount ttrpc service (`virtiofs`, source `hostshare`,
target `/run/mnt/hostshare`) and adds an OCI bind mount to `/host`.

Gotcha that cost us a boot: the kernel probes virtio-mmio shared-memory
regions (DAX window) and expects **length `~0`** at `SHMLen` to mean
"absent". Returning 0 registers a zero-length window and the virtiofs probe
dies with EBUSY (`could not reserve region addr=0x0 len=0x0`). Same fix as
libkrun's mmio transport.

## Troubleshooting (paste me the output if it fails)

| symptom | meaning |
|---|---|
| `hv_vm_create: HV_DENIED` | entitlement didn't apply — run `codesign -dv --entitlements - ./gantry-darwin-arm64` and check `com.apple.security.hypervisor` is there |
| `hv_gic_create: HV_UNSUPPORTED` | macOS < 13, or running under a VM without nested virt |
| `unhandled exception EC=...` | my HVF exit decoder hit a case I didn't implement — paste the line, it's a 5-minute fix |
| guest prints garbage | terminal raw mode — `reset` your terminal after |
| DHCP or DNS fails | inspect `/tmp/gantry-gvproxy.log` and rerun with `GANTRY_DEBUG_NET=1` |
| `virtio-fs: tag <hostshare> not found` | VM started without the share — set `GANTRY_SHARE=...` on the `run-macos.sh` line (it is not a script argument) |
| `could not reserve region addr=0x0 len=0x0` | old binary: MMIO SHM length must read `~0`, rebuild with `go build` |

The HVF boot, vGIC, vtimer, MMIO, EROFS, vsock/ttrpc, virtio-net with
DHCP/gvproxy NAT, and the interactive container path are verified on Apple
Silicon.

## Files you need (all already in the repo)

- `gantry-darwin-arm64` — prebuilt (rebuild: `GOOS=darwin GOARCH=arm64 go build -o gantry-darwin-arm64 .`)
- `nerdbox-kernel-arm64` — 16K-page kernel (macOS)
- `initramfs-shell.cpio.gz` — guest userland (static Go init + busybox)
- `nerdbox-rootfs-arm64.erofs` — the real nerdbox guest rootfs
- `shell-rootfs.erofs` — tiny busybox OCI rootfs attached as `/dev/vdb`
- `hostctl-darwin-arm64` — ttrpc task client + stream relay
- `gvproxy-darwin-arm64` — bundled user-mode NAT/DHCP/DNS provider
- `entitlements.plist`, `run-macos.sh`
