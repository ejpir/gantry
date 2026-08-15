# gantry: microVM sandboxes

**gantry** runs Linux OCI workloads inside lightweight VMs: a standalone Go
VMM and CLI (no Docker, containerd, or libkrun required). KVM on Linux,
Hypervisor.framework on Apple Silicon, experimental WHPX on Windows.

> Experimental. Linux and Apple Silicon macOS are the supported targets.

[![Gantry terminal dashboard demo](assets/gantry-tui.gif)](assets/gantry-tui.gif)

## Install

Download the latest release binary:

```sh
# Linux (arm64 or amd64)
curl -LO https://github.com/ejpir/gantry/releases/latest/download/gantry-linux-arm64
chmod +x gantry-linux-arm64

# macOS (Apple Silicon) — release assets carry an ad-hoc Hypervisor signature
curl -LO https://github.com/ejpir/gantry/releases/latest/download/gantry-darwin-arm64
chmod +x gantry-darwin-arm64
xattr -d com.apple.quarantine gantry-darwin-arm64
```

Or install from source with Go 1.26+:

```sh
go install github.com/ejpir/gantry/cmd/gantry@latest
```

Guest assets: nothing to do — the hardened kernel (`gantry-kernel-<arch>`),
guest rootfs (`nerdbox-rootfs-<arch>.erofs`), and a small default Alpine OCI
image download automatically from the matching release on first start. Leave
the dashboard's OCI image field blank to use that default. Tagged binaries
cache them by release under the OS user cache
(`%LocalAppData%\gantry\assets` on Windows), so an upgrade cannot silently
reuse an older kernel and never needs Administrator access to the executable's
directory. `GANTRY_ARTIFACTS` remains an explicit staging override. A stock
nerdbox kernel is used only when selected with `-kernel`; automatic boots
always use Gantry's owned kernel. Manual fallback: copy the rootfs from a
[nerdbox release](https://github.com/containerd/nerdbox/releases) into
`artifacts/`, or build from source below.

Release integrity: every download is verified against the `.sha256` sidecar
published beside the asset (fail-closed), assets are immutable once
published, and each artifact carries a Sigstore build-provenance
attestation — verify with
`gh attestation verify <file> --repo ejpir/gantry`.

Tagged builds check for a new stable release at most once per day without
holding up the command being run. A cached CLI notice points to
`gantry update`; `gantry version` performs an explicit check. The dashboard
shows an `↑ VERSION` badge when an update is available—press `U` or click the
badge, then confirm to install it. Updates download the matching platform
binary, verify its SHA-256 sidecar and executable format, and atomically
replace the current executable. macOS additionally requires the release's
verified Hypervisor entitlement; Windows completes replacement through a
detached, trusted system process after the dashboard exits. For privilege
safety, Windows self-update refuses elevated processes; install Gantry in a
user-writable location or replace an administrator-managed binary manually.
Running sandboxes are not stopped.

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
# stop/exec, and Traffic / Rules / Mounts / Ports / Secrets views — tab or 1–6
# to switch
./gantry-linux-arm64 tui

# persistent local HTTP/JSON manager over ~/.gantry/manager.sock
./gantry-linux-arm64 serve
```

## Features

- **VM + process isolation** — one VM per sandbox, with separate supervisor,
  network, and VMM processes. The guest-facing VMM worker is confined by Linux
  namespaces/seccomp or macOS Seatbelt; `-process-isolation=required` fails
  closed and `isolation.json` records the verified boundary.
- **Images** — OCI reference/layout, Docker-save tar, or EROFS; verified,
  flattened, and cached by digest. Private registries use standard credential
  helpers (`gantry image pull|login|ls`).
- **Runtimes and sessions** — `crun` by default or in-VM gVisor with
  `-runtime runsc`; concurrent exec sessions and exact exit statuses.
- **Host shares** — host-enforced read-only virtio-fs exports, including
  `@/container/path` aliases. `gantry share add|remove|ls` is live on Linux;
  adding a new host path to a confined macOS VM requires a restart.
- **Networking** — embedded netstack, local networks blocked by default, and
  CIDR/proto/port/DNS egress rules. Policies are replaceable live with
  `gantry net-policy set`; the Traffic view can add an allow/deny override for
  a selected destination using any, TCP, UDP, or ICMP and remove it again.
- **Port publishing** — TCP/UDP host-to-guest forwards, loopback by default:
  `-p 8080:80`; publish/unpublish live with `gantry ports` or the dashboard.
- **Secrets** — `-secret NAME`, `NAME=@file`, or `-secret-file`; values travel
  memory-only to per-exec process specs, never argv, sandbox state, or the
  daemon environment. The Secrets view lists names and can load/delete values
  without ever displaying or persisting them.
- **OAuth sign-in bridge** — enabled by default for agent CLIs (codex, claude,
  pi) that sign in via a localhost callback. The daemon spots the printed
  authorize URL, binds a bounded/approved loopback port on the host, and
  replays the browser callback into the sandbox. Use
  `gantry start NAME -oauth-bridge=false` to opt out;
  `GANTRY_OAUTH_BRIDGE=1|0` is the global enable/disable override.
- **Persistence and resources** — named sandboxes get private locked writable
  ext4 layers plus configurable disk size, memory, vCPUs, and process
  isolation. The disk is formatted in pure Go on first start (no elevation or
  host filesystem tools); dashboard resource edits apply on next boot.
- **Dashboard and import** — create/start/stop/exec plus Traffic, Rules,
  Mounts, Ports, and Secrets views; `gantry import` adopts compatible sandbox
  state without re-pulling or flattening immutable image layers.
- **In-place updates** — cached release notices in the CLI and dashboard,
  verified `gantry update`, and a dashboard confirmation flow that leaves
  running sandboxes untouched.
- **Local manager API** — `gantry serve` provides lifecycle, bounded captured
  exec, operations, and SSE events as HTTP/JSON over a same-user Unix socket;
  see the checked-in [OpenAPI contract](api/managerapi/openapi.yaml).

## Build from source

```sh
./scripts/build.sh        # needs Go 1.26.6+; outputs land in artifacts/
./scripts/mkimage.sh alpine:latest artifacts/alpine.erofs   # rootfs image
./scripts/mkkernel.sh     # build the hardened guest kernel locally
go test ./...
```

| Host | Backend | Status |
|---|---|---|
| Linux arm64 | KVM | Implemented; requires `/dev/kvm` |
| Linux x86-64 | KVM | Verified on EC2 `c5.metal` |
| macOS arm64 | Hypervisor.framework | Verified; macOS 13+ |
| Windows x86-64 | WHPX | Verified on EC2 `m6i.metal`, including SMP |

## Limitations

Not (yet): snapshots. The trusted supervisor runs with the launching user's
privileges; the guest-facing VMM worker is confined on Linux and macOS. On
Windows it runs separately under a verified Job Object process boundary, but
filesystem and ambient-network confinement remain unenforced, so
`-process-isolation=required` fails closed. Writable layers must not be shared
between live VMs.

## Acknowledgements

[containerd/nerdbox](https://github.com/containerd/nerdbox) ·
[gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock) ·
[go-erofs](https://github.com/erofs/go-erofs) ·
[go-fuse](https://github.com/hanwen/go-fuse) ·
[gVisor](https://gvisor.dev/)

## Security & License

Report vulnerabilities privately per [SECURITY.md](SECURITY.md) — please
do not open public issues for boundary bugs. gantry is Apache-2.0
licensed ([LICENSE](LICENSE)); vendored code under `third_party/` keeps
its own license.
