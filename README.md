# gantry: microVM sandboxes

**gantry** runs Linux OCI workloads inside lightweight VMs: a standalone Go
VMM and CLI (no Docker, containerd, or libkrun required). KVM on Linux,
Hypervisor.framework on Apple Silicon, experimental WHPX on Windows.

> Experimental. Linux and Apple Silicon macOS are the supported targets.

## Install

Download the latest release binary:

```sh
# Linux (arm64 or amd64)
curl -LO https://github.com/ejpir/gantry/releases/latest/download/gantry-linux-arm64
chmod +x gantry-linux-arm64

# macOS (Apple Silicon) — also needs an ad-hoc signature + entitlement
curl -LO https://github.com/ejpir/gantry/releases/latest/download/gantry-darwin-arm64
curl -LO https://raw.githubusercontent.com/ejpir/gantry/main/config/entitlements.plist
codesign --force --sign - --entitlements entitlements.plist gantry-darwin-arm64
xattr -d com.apple.quarantine gantry-darwin-arm64
```

Two guest assets are needed before first run:

- **Rootfs**: copy `nerdbox-rootfs-<arch>.erofs` from a
  [nerdbox release](https://github.com/containerd/nerdbox/releases) into
  `artifacts/` (or build from source, below).
- **Kernel**: nothing to do — `gantry-kernel-<arch>` downloads automatically
  from the latest release on first start.

## Use

```sh
# one-shot: pull, boot, run, tear down
./gantry-linux-arm64 exec -image alpine:latest -- /bin/sh

# persistent sandbox
./gantry-linux-arm64 start dev -image debian:bookworm-slim
./gantry-linux-arm64 exec dev -- /bin/bash
./gantry-linux-arm64 ls
./gantry-linux-arm64 stop dev      # resume / delete work as expected

# interactive dashboard (auto-starts in a terminal): cards, create/start/
# stop/exec, and Traffic / Rules / Mounts views — tab or 1–4 to switch
./gantry-linux-arm64 tui
```

## Features

- **Images** — OCI reference, OCI layout, Docker-save tar, or EROFS file;
  flattened and cached automatically. `gantry image pull alpine:latest`,
  `gantry image ls`.
- **Host shares** — export directories over virtio-fs:
  `-share repo="$PWD@/workspace,ro"`. Hot-add without a restart:
  `gantry share add dev data="$PWD/data,ro"` (also `ls`/`remove`; the
  dashboard's Mounts view does the same). Details:
  [docs/hot-add-shares.md](docs/hot-add-shares.md).
- **Networking** — embedded netstack; public internet allowed, local networks
  blocked by default (`-allow-local-net` to opt in). Egress policies with
  CIDR/proto/port/DNS rules: `-net-policy examples/llm-only.json`.
- **Runtimes** — `crun` by default; in-VM gVisor with `-runtime runsc`
  (rootfs via `./scripts/mkrootfs-gvisor.sh`).
- **Secrets** — `-secret GITHUB_TOKEN` injects from the environment, never
  via argv or sandbox state.
- **Persistence** — named sandboxes get a private writable layer at
  `~/.gantry/rwlayers/<name>.ext4` (`-rw=false` to disable).

## Build from source

```sh
./scripts/build.sh        # needs Go 1.26.5+; outputs land in artifacts/
./scripts/mkimage.sh alpine:latest artifacts/alpine.erofs   # rootfs image
./scripts/mkkernel.sh     # build the hardened guest kernel locally
go test ./...
```

| Host | Backend | Status |
|---|---|---|
| Linux arm64 | KVM | Implemented; requires `/dev/kvm` |
| Linux x86-64 | KVM | Verified on EC2 `m6i.metal` |
| macOS arm64 | Hypervisor.framework | Verified; macOS 13+ |
| Windows x86-64 | WHPX | Cross-build only, not boot-verified |

## Docs and limitations

- [docs/macos.md](docs/macos.md) — macOS specifics, signing, virtio devices
- [docs/windows-shares.md](docs/windows-shares.md) — Windows NTFS passthrough
- [docs/hardening-audit.md](docs/hardening-audit.md) — hardened kernel, guest
  init, and the threat model behind them
- [docs/aws-kvm-test.md](docs/aws-kvm-test.md) — native KVM testing on EC2

Not (yet): Windows boot verification, snapshots, port publishing. The VMM
runs with the launching user's host privileges; writable layers must not be
shared between live VMs.

## Acknowledgements

[containerd/nerdbox](https://github.com/containerd/nerdbox) ·
[gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock) ·
[go-erofs](https://github.com/erofs/go-erofs) ·
[go-fuse](https://github.com/hanwen/go-fuse) ·
[gVisor](https://gvisor.dev/)
