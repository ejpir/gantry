# gantry: microVM sandboxes

**gantry** runs Linux OCI workloads inside lightweight VMs. It is a standalone
Go VMM and CLI, not a containerd runtime shim. It uses KVM on Linux and
Hypervisor.framework on Apple Silicon macOS. Windows WHPX support is
experimental.

Gantry reuses the EROFS rootfs, `vminitd`, and task APIs from
[nerdbox](https://github.com/containerd/nerdbox), but does not require Docker,
containerd, or libkrun. The guest kernel is Gantry's own hardened build
(nerdbox-derived baseline plus memory-safety and info-leak hardening; see
[docs/hardening-audit.md](docs/hardening-audit.md)).

- One-shot and persistent sandboxes
- OCI registry, OCI layout, Docker-save, and EROFS images
- Digest-keyed image cache
- Embedded networking and egress policy
- virtio-fs host shares and persistent ext4 layers
- `crun` or optional in-VM gVisor `runsc`

> Experimental. Native Linux and Apple Silicon macOS are the supported targets.

## Status

| Host | Backend | Status |
|---|---|---|
| Linux arm64 | KVM | Implemented; requires `/dev/kvm` |
| Linux x86-64 | KVM | Verified on EC2 `m6i.metal` |
| macOS arm64 | Hypervisor.framework | Verified; macOS 13+ |
| Windows x86-64 | WHPX | Native NTFS virtio-fs; cross-build only, not boot-verified |

## Getting started

Requirements:

- Go 1.26.5+
- A guest rootfs in `artifacts/`:

  ```text
  artifacts/nerdbox-rootfs-arm64.erofs
  artifacts/nerdbox-rootfs-x86_64.erofs
  ```

- The guest kernel downloads automatically from the GitHub release page on
  first start (`gantry-kernel-<arch>`, and the 4K-page variant for
  `-runtime runsc` on arm64). To build it locally instead:
  `./scripts/mkkernel.sh`
- Linux: `/dev/kvm`
- macOS: Apple Silicon, macOS 13+

Build:

```sh
./scripts/build.sh
```

Build outputs and guest assets are kept in the ignored `artifacts/` directory.

## Running

Set the binary for the host:

```sh
G=./artifacts/gantry                 # Linux
# G=./artifacts/gantry-darwin-arm64  # macOS
```

The interactive dashboard provides responsive sandbox cards, create/start/stop,
exec, inspect, remove, refresh, keyboard navigation, and mouse controls. Its
Traffic, Rules, and Mounts views show per-sandbox network destinations and byte
counts, effective egress policy, and host-to-guest share mappings. Traffic is
captured from VM boot and retained across stop/resume cycles; only destination
metadata and counters are stored, never packet payloads. A sandbox already
running when Gantry is upgraded must be stopped and started once from the
new dashboard to enable capture in its VMM process. The dashboard starts
automatically when `gantry` is run in an interactive terminal, or can be opened
explicitly:

```sh
$G tui
```

Use `tab`/`shift+tab`, `1`–`4`, or the mouse to switch dashboard views. The
New Sandbox dialog also selects the guest runtime (`crun`/`runsc`) and the
kernel (auto-download, or any build staged in `artifacts/`).

Run a container. OCI references are pulled and cached automatically:

```sh
$G exec -image alpine:latest -- /bin/sh
$G exec -image debian:bookworm-slim -- apt-get update
```

Run a persistent sandbox:

```sh
$G start dev -image debian:bookworm-slim
$G exec dev -- /bin/bash
$G ls
$G stop dev
$G resume dev             # restart with its saved configuration
$G delete dev
```

On macOS, use the signing wrapper:

```sh
./scripts/run-macos.sh exec -image alpine:latest -- /bin/sh
./scripts/run-macos.sh start dev -image debian:bookworm-slim
./artifacts/gantry-darwin-arm64 exec dev -- /bin/sh
```

For a downloaded macOS binary, apply a temporary ad-hoc signature and remove
macOS quarantine before running it:

```sh
codesign --force --sign - --timestamp=none gantry-darwin-arm64
codesign --verify --verbose gantry-darwin-arm64
xattr -d com.apple.quarantine gantry-darwin-arm64
./gantry-darwin-arm64
```

A named sandbox gets a private, persistent layer at
`~/.gantry/rwlayers/<name>.ext4`. Use `-rw=false` to disable it.

## Images

`-image` accepts an EROFS file, OCI layout directory, Docker-save tar, or OCI
reference. Images are flattened into EROFS and cached under
`~/.gantry/images`.

```sh
$G image pull alpine:latest
$G image ls
$G image pull --platform linux/amd64 debian:bookworm-slim
$G image prune
```

For a manual Docker-based conversion:

```sh
./scripts/mkimage.sh alpine:latest artifacts/alpine.erofs
```

## Shares and networking

Export host directories over virtio-fs. Use `,ro` for a read-only share and
`@/path` to choose its container target:

```sh
$G start dev -image python:3.12 \
  -share repo="$PWD@/workspace,ro"
$G exec dev -- sh -c 'cd /workspace && python -m pytest'
```

Attach another directory without restarting the VM (it appears immediately at
`/host/<tag>` in the long-running container):

```sh
$G share add dev data="$PWD/data,ro"
$G share ls dev
$G share remove dev data
```

Live share changes update `sandbox.json` by default; `--ephemeral` applies
only to the current boot. The dashboard's Mounts page exposes the same
operations with `a` (add), `d` (remove), and `r` (replace).

On Windows, host shares use the native NTFS passthrough backend. Local NTFS
paths such as `C:\Users\me\project` are supported; UNC/network drives,
FAT/exFAT/ReFS, and export roots that are reparse points are rejected.

See [Hot-Adding Host Shares](docs/hot-add-shares.md) and the
[Windows native passthrough design](docs/windows-shares.md) for implementation
notes.

The default network allows the public internet but blocks local networks.

```sh
$G start dev -allow-local-net
$G start agent -image python:3.12 \
  -net-policy examples/llm-only.json
```

Policies support ordered CIDR, protocol, port, and DNS-domain rules. Use
`default: deny` plus explicit IP rules when DNS filtering is insufficient.

## Runtime options

`crun` is the default. For gVisor inside the VM:

```sh
./scripts/mkrootfs-gvisor.sh artifacts/nerdbox-rootfs-arm64.erofs
# arm64 only: the 4K-page kernel downloads automatically,
# or build it with: PAGES=4k ./scripts/mkkernel.sh
$G start hardened -runtime runsc -image alpine:latest
```

Inject workload secrets without putting values in argv or sandbox state:

```sh
export GITHUB_TOKEN=...
$G start agent -secret GITHUB_TOKEN -image python:3.12 \
  -net-policy examples/llm-only.json
```

`gantry pi` runs the pi coding agent in a project sandbox. Build its image
with `./scripts/mkpiimage.sh`.

## Debugging

```sh
$G run -kernel artifacts/gantry-kernel-arm64 \
  -initrd artifacts/initramfs-shell.cpio.gz
./scripts/run-qemu-test.sh       # no KVM required
./scripts/run-qemu-shell.sh
```

Boot/runtime debug knobs (environment):

- `GANTRY_DEBUG_BOOT=1` — full kernel printk on the console instead of
  warnings only.
- `GANTRY_EXTRA_CMDLINE="crunshim.debug=1"` — with `-runtime runsc`,
  forwards runsc's `--debug --debug-log /dev/console`: the sentry's boot
  log, which otherwise dies silently inside the VM, lands in console.log.
- `GANTRY_NO_CMDLINE_HARDENING=1` — boots without the hardening
  boot-params/sysctls, for bisecting guest boot problems.
- `GANTRY_BOOT_TIMING=1` — per-phase boot timings in daemon.log.

## Layout

```text
cmd/gantry/       CLI
cmd/hostctl/      task client
internal/vmm/     KVM, HVF, WHPX, boot, chipset
internal/virtio/  virtio devices
internal/image/   OCI resolution and EROFS cache
internal/netpol/  egress policy
internal/sandbox/ lifecycle and session broker
guest/            guest programs
scripts/          build, image, kernel, and test scripts
artifacts/        ignored build outputs and guest assets
```

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
```

Native KVM/HVF testing needs the corresponding host and guest assets. See
[`docs/aws-kvm-test.md`](docs/aws-kvm-test.md) and [`docs/macos.md`](docs/macos.md).

## Limitations

- Windows boot and Windows virtio-fs VM integration are not verified.
- No snapshots, CPU throttling, or port publishing.
- The VMM runs with the user's host privileges.
- DNS allowlists do not constrain connections to already-known IP addresses.
- Writable layers persist on host storage and must not be shared by live VMs.

## Acknowledgements

- [containerd/nerdbox](https://github.com/containerd/nerdbox)
- [gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock)
- [go-erofs](https://github.com/erofs/go-erofs)
- [go-fuse](https://github.com/hanwen/go-fuse)
- [gVisor](https://gvisor.dev/)
