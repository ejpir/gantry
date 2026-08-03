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

Guest assets: nothing to do — the hardened kernel (`gantry-kernel-<arch>`)
and guest rootfs (`nerdbox-rootfs-<arch>.erofs`) download automatically from
the latest release on first start. Manual fallback: copy the rootfs from a
[nerdbox release](https://github.com/containerd/nerdbox/releases) into
`artifacts/`, or build from source below.

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
  dashboard's Mounts view does the same).
- **Networking** — embedded netstack; public internet allowed, local networks
  blocked by default (`-allow-local-net` to opt in). Egress policies with
  CIDR/proto/port/DNS rules: `-net-policy examples/llm-only.json`.
- **Port publishing** — expose guest services on the host:
  `-p 8080:80` (loopback by default; `-p 0.0.0.0:8080:80` opts into LAN,
  `/udp` for UDP). Hot publish on a running sandbox:
  `gantry ports publish dev 8081:8080` (also `ls`/`unpublish`; the
  dashboard's Ports view does the same).
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

## Limitations

Not (yet): Windows boot verification, snapshots. The VMM
runs with the launching user's host privileges; writable layers must not be
shared between live VMs.

## Acknowledgements

[containerd/nerdbox](https://github.com/containerd/nerdbox) ·
[gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock) ·
[go-erofs](https://github.com/erofs/go-erofs) ·
[go-fuse](https://github.com/hanwen/go-fuse) ·
[gVisor](https://gvisor.dev/)
