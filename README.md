# Gantry

[![CI](https://github.com/ejpir/gantry/actions/workflows/ci.yml/badge.svg)](https://github.com/ejpir/gantry/actions/workflows/ci.yml)

Gantry runs OCI images in lightweight Linux microVMs. It is a standalone Go
VMM and CLI; Docker, containerd, QEMU, and libkrun are not required.

It uses KVM on Linux, Hypervisor.framework on Apple silicon, and WHPX on
Windows.

> Gantry is experimental. Linux and Apple silicon macOS are supported. Windows
> support is experimental.

[![Gantry terminal dashboard demo](assets/gantry-tui.gif)](assets/gantry-tui.gif)

## Install

Download the binary for your host from the
[latest release](https://github.com/ejpir/gantry/releases/latest).

### Linux

```sh
# Use amd64 or arm64 as appropriate.
curl -L https://github.com/ejpir/gantry/releases/latest/download/gantry-linux-amd64 -o gantry
chmod +x gantry
```

### macOS (Apple silicon)

```sh
curl -L https://github.com/ejpir/gantry/releases/latest/download/gantry-darwin-arm64 -o gantry
chmod +x gantry
xattr -d com.apple.quarantine gantry
```

### Windows (x86-64)

```powershell
Invoke-WebRequest https://github.com/ejpir/gantry/releases/latest/download/gantry-windows-amd64.exe -OutFile gantry.exe
```

The first sandbox start downloads and verifies the matching guest kernel,
root filesystem, and default image.

## Quick start

Run a disposable container in a fresh VM:

```sh
./gantry exec -image alpine:latest -- /bin/sh
```

Create and reuse a named sandbox:

```sh
./gantry start dev -image debian:bookworm-slim
./gantry exec dev -- /bin/bash
./gantry stop dev
./gantry resume dev
./gantry delete dev
```

Open the terminal dashboard:

```sh
./gantry tui
```

## Highlights

- OCI registry images, layouts, archives, Docker saves, and EROFS images
- Persistent sandboxes with configurable CPU, memory, disk, and runtime
- `crun` by default, with optional in-VM gVisor (`-runtime runsc`)
- Host shares, egress policy, proxy routing, traffic inspection, and ports
- Local SSH and VS Code Dev Containers support
- In-memory secrets, OAuth custody, and a credential-injecting MCP gateway
- Terminal dashboard and local HTTP/JSON manager API

See the [Gantry manual](docs/gantry/README.md) for usage, configuration,
networking, credentials, architecture, and the security model. Run
`gantry --help` for the complete CLI reference.

## Platforms

| Host | Backend | Status |
|---|---|---|
| Linux arm64 | KVM | Supported; requires `/dev/kvm` |
| Linux x86-64 | KVM | Supported; verified on EC2 `c5.metal` |
| macOS arm64 | Hypervisor.framework | Supported on macOS 13+ |
| Windows x86-64 | WHPX | Experimental; verified on EC2 `m6i.metal` |

## Startup performance

Measured cold-guest startup to RPC readiness with warm host file caches:

| Host | Backend | Configuration | Observed startup |
|---|---|---|---:|
| Linux arm64 | KVM | 1 vCPU, 512 MiB, network off | **72.9 ms** median CLI-to-ready |
| macOS arm64 | Hypervisor.framework | 1 vCPU, 512 MiB, network off | **94.1 ms** median CLI-to-ready |
| Linux x86-64 | KVM | 1 vCPU, 512 MiB, network off | **177.8 ms** median CLI-to-ready |
| Windows x86-64 | WHPX | 1 vCPU, 512 MiB, split VMM worker | **approximately 400 ms** daemon-to-ready (371–446 ms observed) |

Linux and macOS report full CLI latency. The experimental Windows result is a
native WHPX daemon-to-ready range. See
[`scripts/bench-boot-scaling.sh`](scripts/bench-boot-scaling.sh) and
[`scripts/aws-whpx`](scripts/aws-whpx) to reproduce these measurements.

## Isolation and limitations

Each sandbox runs in its own VM. The trusted supervisor runs as the user who
launched Gantry. In the default `auto` mode, guest-facing work is split into
confined workers where the host supports it:

- Linux uses namespaces, capability removal, Landlock, and seccomp.
- macOS uses role-specific Seatbelt profiles.
- Windows uses one-process Jobs and AppContainers: VMM device emulation and MCP
  run without network capabilities, while networking uses a separate worker
  with an exact capability set. A narrow Job-confined broker owns the WHPX
  partition because WHPX cannot run inside the zero-capability AppContainer.

Workers actively verify their filesystem, network, and process restrictions.
Use `-process-isolation=required` to fail startup unless the full required
boundary is established. On Windows, required mode rejects host-loopback
access and published ports rather than weakening AppContainer isolation.

Gantry is not yet a hardened boundary for hostile public multi-tenancy.
Snapshots and rollback are not supported; use `gantry export` on a stopped
sandbox for a portable OCI archive. Writable layers are mutable and may be
attached to only one running VM at a time.

See [Security](docs/gantry/security.md) for the complete threat model and
platform-specific limits.

## Updates

Tagged builds check for stable releases in the background. Update explicitly
with:

```sh
./gantry update
```

Release binaries and guest assets are SHA-256 verified. Release artifacts also
include Sigstore build provenance.

## Build from source

Go 1.26.6 or newer is required.

```sh
go install github.com/ejpir/gantry/cmd/gantry@latest

# Or from a checkout:
./scripts/build.sh
./scripts/mkimage.sh alpine:latest artifacts/alpine.erofs
./scripts/mkkernel.sh
go test ./...
```

Set `GANTRY_ARTIFACTS` to use an explicit guest-asset directory.

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
Do not open public issues for sandbox-boundary vulnerabilities.

## Acknowledgements

[containerd/nerdbox](https://github.com/containerd/nerdbox) ·
[gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock) ·
[go-erofs](https://github.com/erofs/go-erofs) ·
[go-fuse](https://github.com/hanwen/go-fuse) ·
[gVisor](https://gvisor.dev/)

Gantry is licensed under [Apache-2.0](LICENSE). Vendored code in `third_party/`
retains its original license.
