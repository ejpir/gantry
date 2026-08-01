# gantry: standalone microVM sandboxes

**gantry** is a small, standalone Go VMM and sandbox CLI for running Linux
OCI workloads inside a virtual machine. It uses KVM on Linux, Hypervisor.framework
on Apple Silicon macOS, and has an experimental WHPX backend for Windows.

Gantry reuses the Linux guest assets and `vminitd`/task APIs from Docker's
[nerdbox](https://github.com/containerd/nerdbox), but it is **not** a
containerd runtime shim. It runs without Docker, containerd, libkrun, or a
separately installed host service; persistent sandboxes use a small daemon
spawned by the same `gantry` binary.

> **Experimental:** gantry is under active development. Read the platform
> status and limitations below before using it for untrusted workloads.

- One-shot or long-lived, one-VM-per-sandbox execution
- OCI image references, OCI layouts, `docker save` archives, and EROFS files
- Digest-keyed image cache with pure-Go layer flattening and EROFS creation
- Embedded DHCP, DNS, NAT, and egress policy enforcement
- Explicit host-directory sharing over virtio-fs, including host-enforced `,ro`
- Persistent writable layers backed by ext4
- `crun` by default, with optional gVisor `runsc` defense in depth
- Workload secrets delivered without putting values in sandbox state or argv

## Platform status

| Host | Backend | Status |
|---|---|---|
| Linux arm64 | KVM | Builds and requires `/dev/kvm`; guest path is also covered by QEMU tests |
| Linux x86-64 | KVM | Verified end-to-end on an EC2 `m6i.metal` host |
| macOS arm64 | Hypervisor.framework | Verified on Apple Silicon; macOS 13+ |
| Windows x86-64 | WHPX | Cross-build and unit tests only; real Windows boot is not verified |

Host-directory sharing is currently unavailable on Windows. The normal
supported development targets are Linux and Apple Silicon macOS.

## How it compares with nerdbox

[nerdbox](https://github.com/containerd/nerdbox) integrates VM-isolated
containers into containerd as a runtime shim. Gantry takes a different
shape:

| nerdbox | gantry |
|---|---|
| containerd runtime shim | standalone `gantry` CLI and VMM |
| libkrun/libsailor VMM | Go VMM with KVM/HVF/WHPX backends |
| containerd controls the VM | `gantry start`, `exec`, `stop`, and `delete` control it |
| containerd snapshotter supplies images | host-side OCI pull/flatten/cache supplies one EROFS image |
| guest networking supplied by the host integration | embedded gvisor-tap-vsock netstack, with optional external gvproxy |

The projects share the nerdbox guest conventions: the kernel/rootfs image,
vsock control path, `vminitd`, and containerd task/mount APIs.

## Getting started

### Requirements

- Go **1.26.5** or newer
- A matching nerdbox kernel and guest rootfs in the repository root:

  ```text
  nerdbox-kernel-arm64       nerdbox-rootfs-arm64.erofs
  nerdbox-kernel-x86_64      nerdbox-rootfs-x86_64.erofs
  ```

  These large guest assets are intentionally ignored by Git. Use the assets
  from the Docker Sandbox/nerdbox distribution or provide your own compatible
  images. The arm64 kernel shipped by nerdbox uses 16K pages; the x86-64
  kernel uses 4K pages.
- Linux: access to `/dev/kvm` for native execution
- Apple Silicon macOS: macOS 13 or newer. `run-macos.sh` ad-hoc signs the
  binary with `com.apple.security.hypervisor`.

Build the VMM:

```sh
./build.sh
```

On Linux this produces `./gantry`. On Apple Silicon it produces
`./gantry-darwin-arm64` and signs it. If a static arm64 BusyBox is available,
`build.sh` also creates the debug initramfs images used by `gantry run`.

### Run a one-shot container

Image references are pulled and cached on first use. The guest architecture
is selected from the kernel rather than from the host process:

```sh
./gantry exec -image alpine:latest -- /bin/sh
./gantry exec -image debian:bookworm-slim -- apt-get update
```

The command's exit status is returned by `gantry exec`. With no command, the
image's `Entrypoint` and `Cmd` are used; plain EROFS files fall back to
`/bin/sh`.

On Apple Silicon, use the wrapper, which builds and signs before running:

```sh
./run-macos.sh exec -image alpine:latest -- /bin/sh
```

### Run a persistent sandbox

A named sandbox owns a VM daemon and a per-sandbox writable layer. Multiple
`exec` sessions may attach to the same VM, including concurrently:

```sh
./gantry start dev -image debian:bookworm-slim
./gantry exec dev -- /bin/bash
./gantry exec dev -- uname -a
./gantry ls
./gantry stop dev
./gantry delete dev
```

For macOS, use `run-macos.sh start|stop|ls|delete` and attach with the signed
binary:

```sh
./run-macos.sh start dev -image debian:bookworm-slim
./gantry-darwin-arm64 exec dev -- /bin/sh
./run-macos.sh stop dev
```

The default writable layer for a named sandbox is
`~/.gantry/rwlayers/<name>.ext4` and is created on demand. Disable the overlay
with `-rw=false`, or select an explicit layer with `-rwlayer`. A layer is
paired with the image it was created for and must not be shared by two live
VMs.

## Images

`-image` accepts:

1. an existing `.erofs` file;
2. an OCI layout directory containing `oci-layout`;
3. a `docker save`/OCI tar archive; or
4. an OCI reference such as `alpine:latest` or
   `ghcr.io/example/app@sha256:...`.

Registry images are flattened into one 4K-block EROFS file and cached under
`~/.gantry/images` by manifest digest. The image config is retained, so
`Env`, `Entrypoint`, `Cmd`, `User`, and `WorkingDir` are honored.

```sh
./gantry image pull alpine:latest
./gantry image pull --platform linux/amd64 debian:bookworm-slim
./gantry image ls
./gantry image rm alpine:latest
./gantry image prune
```

Private registries can use Docker/Podman credential configuration, or gantry's
credential helpers:

```sh
printf '%s' "$TOKEN" | ./gantry image login ghcr.io \
  -u USER --password-stdin
./gantry image credentials
./gantry image logout ghcr.io
```

Registry credentials are used on the host while building the image and are
never sent into the guest. For a manual, Docker-based EROFS conversion,
`mkimage.sh` remains available; it requires Docker and erofs-utils on Linux.

## Sharing files and writable roots

Export host directories with virtio-fs. The optional `@CONTAINER_PATH` selects
the target; without it, shares are mounted below `/host`:

```sh
# Read-only project at /workspace.
./gantry start dev -image python:3.12 \
  -share repo="$PWD@/workspace,ro"
./gantry exec dev -- sh -c 'cd /workspace && python -m pytest'

# Multiple shares default to /host/<tag>.
./gantry start dev -image alpine:latest \
  -share code="$PWD,ro" \
  -share data="$HOME/data"
```

Read-only shares are enforced in the host-side FUSE handler as well as in the
guest mount configuration. Share names are contained and cannot escape the
exported host directory through `..` paths or symlinks.

## Network policy

Networking uses an embedded gvisor-tap-vsock netstack by default; no external
`gvproxy` process is needed. The default posture is **public internet allowed,
local network denied**. RFC1918, loopback, link-local addresses (including the
cloud metadata endpoint), multicast, and the host NAT alias are blocked.

```sh
# Default: internet, but not the LAN.
./gantry start dev -image alpine:latest

# Permit local-network access explicitly.
./gantry start dev -image alpine:latest -allow-local-net

# Default-deny policy with a DNS domain allowlist.
./gantry start agent -image python:3.12 \
  -net-policy examples/llm-only.json
```

A policy file can combine ordered CIDR/protocol/port rules with DNS domain
allowlists:

```json
{
  "default": "deny",
  "allowLocal": false,
  "rules": [
    { "action": "allow", "proto": "tcp", "ports": "443" }
  ],
  "allowDomains": ["pypi.org", "files.pythonhosted.org"]
}
```

DNS allowlists learn the IPs returned for approved names and cap their TTL.
They are a convenience layer, not a substitute for explicit IP rules: a
workload that already knows an IP can avoid DNS. Policy enforcement requires
the embedded netstack and cannot be combined with `-gvproxy`.

## Secrets

Secrets are resolved by the host and injected into workload process
specifications. Values are not written to `sandbox.json` or command-line
arguments; `gantry start` passes them to the per-sandbox daemon over a
one-time stdin handshake:

```sh
export GITHUB_TOKEN=...
./gantry start agent -image python:3.12 \
  -secret GITHUB_TOKEN \
  -net-policy examples/llm-only.json

# Or read a value from a file without putting it in argv.
./gantry start agent -image python:3.12 \
  -secret API_KEY=@$HOME/.config/my-api-key
```

`-secret-file` accepts dotenv-style `NAME=VALUE` entries. Secret names may
appear in `gantry ls`, but values remain in daemon memory for the VM lifetime.
The workload can of course read or print its own secrets; pair secret
injection with a restrictive egress policy.

## gVisor inside the VM

`crun` is the default guest runtime. For an additional userspace-kernel
boundary, build the gVisor rootfs variant and, on arm64, the required 4K-page
kernel:

```sh
./mkrootfs-gvisor.sh nerdbox-rootfs-arm64.erofs
./mkkernel-4k.sh
./gantry start hardened -runtime runsc -image alpine:latest
./gantry exec hardened -- /bin/sh
```

On x86-64 the stock kernel already uses 4K pages. `runsc` uses its systrap
platform inside the guest; it is slower for syscall-heavy workloads and does
not provide nested `/dev/kvm`.

## Coding-agent integration

The `gantry pi` command keeps a project-specific persistent sandbox and runs
the [pi coding agent](https://github.com/badlogic/pi-mono) inside the VM:

```sh
./mkpiimage.sh
./gantry pi -image ./pi-agent.tar \
  -net-policy examples/llm-only.json
./gantry pi                         # reattach to this project's sandbox
```

The project is mounted at `/workspace`. By default the host's `~/.pi/agent`
directory is shared into the guest so authentication and sessions are reused;
use `-pi-auth=false` when that is not wanted. See
[`integrations/pi-container/README.md`](integrations/pi-container/README.md)
and [`docs/agent-sandboxing.md`](docs/agent-sandboxing.md) for the broader
agent-sandboxing model.

## Low-level and debug flows

`gantry run` boots a kernel with either the project debug initramfs or a real
nerdbox rootfs. It is useful for bring-up and guest-console debugging:

```sh
./gantry run -kernel nerdbox-kernel-arm64 \
  -initrd initramfs-shell.cpio.gz

# No KVM? Guest-side smoke tests use QEMU TCG.
./run-qemu-test.sh
./run-qemu-shell.sh
```

For the two-terminal task.v3 flow, start a VM with `run-macos.sh container`
and use `hostctl` in the other terminal. The normal one-shot and persistent
`gantry exec` commands wrap this flow automatically.

## Architecture

```text
host
└── gantry CLI / sandbox daemon
    ├── KVM (Linux) / Hypervisor.framework (macOS) / WHPX (Windows)
    ├── virtio-mmio: blk, net, vsock, fs, rng, rtc
    ├── embedded netstack + network policy
    └── Linux guest
        ├── nerdbox kernel + EROFS rootfs
        ├── vminitd (PID 1, ttrpc over vsock)
        └── crun or runsc → OCI workload
```

The main packages are:

| Package | Purpose |
|---|---|
| `internal/vmm` | machine assembly, boot protocols, hypervisor backends, chipset |
| `internal/virtio` | virtio-mmio transport and block/net/vsock/fs/rng/rtc devices |
| `internal/vnet` | embedded DHCP/DNS/NAT netstack |
| `internal/netpol` | frame-level egress policy and DNS allowlisting |
| `internal/image` | OCI resolution, registry auth, flattening, EROFS cache |
| `internal/sandbox` | image/config resolution, lifecycle, daemon, session broker |
| `internal/client` | ttrpc bundle/task/mount APIs and stdio streaming |
| `guest/init` | static debug guest PID 1 |

## Development and testing

The unit tests do not require KVM, root, or a running guest:

```sh
go test ./...
go test -race ./...
go vet ./...
```

Cross-builds are covered for Linux arm64/amd64, macOS arm64, and Windows
amd64 in CI. Native KVM/HVF validation additionally requires the corresponding
host and guest assets; see [`docs/aws-kvm-test.md`](docs/aws-kvm-test.md) for
the x86-64 KVM test harness.

## Limitations and threat model

- The VMM process still runs with the user's normal host privileges; there is
  no seccomp/pledge sandbox around the device model yet.
- The guest, virtio descriptors, and host-share requests are treated as an
  adversarial boundary, but a hand-written VMM remains attack surface.
- There is no snapshot/restore, CPU throttling, or port publishing yet.
- Windows WHPX is not a supported validation target and does not support
  virtio-fs shares.
- DNS domain filtering cannot constrain connections to IP addresses a guest
  already knows; use `default: deny` and explicit rules for hard guarantees.
- A writable layer persists on host storage. Do not attach the same layer to
  two running VMs or use a layer with a different image.

## Acknowledgements

- [containerd/nerdbox](https://github.com/containerd/nerdbox) for the guest
  kernel, rootfs, vminitd protocol, and the project this interoperates with.
- [gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock) for the
  embedded user-mode network stack.
- [go-erofs](https://github.com/erofs/go-erofs) and
  [go-fuse](https://github.com/hanwen/go-fuse) for EROFS and virtio-fs support.
- [gVisor](https://gvisor.dev/) for the optional in-guest userspace kernel.
- The KVM, Hypervisor.framework, and Windows Hypervisor Platform projects.
