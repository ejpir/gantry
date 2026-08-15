# Gantry

[![CI](https://github.com/ejpir/gantry/actions/workflows/ci.yml/badge.svg)](https://github.com/ejpir/gantry/actions/workflows/ci.yml)

Gantry runs OCI images in lightweight Linux microVMs. It is a standalone Go
VMM and CLI: Docker, containerd, and libkrun are not required.

Gantry uses KVM on Linux, Hypervisor.framework on Apple Silicon, and WHPX on
Windows.

> Gantry is experimental. Linux and Apple Silicon macOS are the supported
> targets; Windows support is still experimental.

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

### macOS (Apple Silicon)

```sh
curl -L https://github.com/ejpir/gantry/releases/latest/download/gantry-darwin-arm64 -o gantry
chmod +x gantry
xattr -d com.apple.quarantine gantry
```

### Windows (x86-64, experimental)

```powershell
Invoke-WebRequest https://github.com/ejpir/gantry/releases/latest/download/gantry-windows-amd64.exe -OutFile gantry.exe
```

The first sandbox start downloads and verifies the matching guest kernel,
root filesystem, and default Alpine image automatically.

## Quick start

Run a disposable container in a fresh VM:

```sh
./gantry exec -image alpine:latest -- /bin/sh
```

Create a persistent sandbox and reconnect to it later:

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

List sandboxes or start the local HTTP/JSON manager:

```sh
./gantry ls
./gantry serve
```

The manager listens on `~/.gantry/manager.sock`. Its API is documented in the
[OpenAPI contract](api/managerapi/openapi.yaml).

## What Gantry supports

- **OCI images:** registry references, OCI layouts, Docker save archives, and
  EROFS images. Images are flattened, verified, and cached by digest.
- **Persistent sandboxes:** configurable vCPUs, memory, writable disk, runtime,
  networking, and process isolation.
- **Runtimes:** `crun` by default, or in-VM gVisor with `-runtime runsc`.
- **Host shares:** read-only virtio-fs exports, with live add/remove on Linux.
- **Networking:** deny-by-default access to local networks, live egress rules,
  DNS allowlists, traffic inspection, and TCP/UDP port publishing.
- **Secrets:** values are delivered in memory to an exec session and are never
  stored in sandbox state or command-line arguments.
- **Agent sign-in:** localhost OAuth callbacks for Codex, Claude, and Pi can be
  bridged into a sandbox automatically.
- **Dashboard:** create, start, stop, and enter sandboxes; manage traffic,
  rules, mounts, ports, and secrets.

Run `gantry --help` or a command with `--help` for the complete CLI reference.

## Updates

Tagged builds check for new stable releases in the background. The CLI prints
an update notice, and the dashboard shows an `↑ VERSION` badge.

```sh
./gantry version
./gantry update
```

Updates are downloaded beside the installed binary, verified, and replaced
atomically. Updating does not stop running sandboxes. On Windows, run Gantry
unelevated from a user-writable installation; administrator-managed installs
must be updated manually.

Release binaries and guest assets are verified against their SHA-256 sidecars.
Release artifacts also include Sigstore build provenance:

```sh
gh attestation verify <file> --repo ejpir/gantry
```

## Platforms

| Host | Backend | Status |
|---|---|---|
| Linux arm64 | KVM | Implemented; requires `/dev/kvm` |
| Linux x86-64 | KVM | Verified on EC2 `c5.metal` |
| macOS arm64 | Hypervisor.framework | Verified on macOS 13+ |
| Windows x86-64 | WHPX | Experimental; verified on EC2 `m6i.metal` |

## Isolation and limitations

Each sandbox runs in its own VM. The trusted supervisor runs with the launching
user's privileges. On Linux and macOS, the guest-facing VMM worker is further
confined with namespaces and seccomp or Seatbelt. Use
`-process-isolation=required` to fail closed if that boundary cannot be
established.

Windows uses a separate VMM worker and Job Object, but host filesystem and
ambient-network confinement are not yet enforced. Required isolation mode
therefore fails closed on Windows.

Snapshots are not yet supported. Writable layers must not be shared between
running VMs.

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

Set `GANTRY_ARTIFACTS` to use an explicit guest-asset directory for local,
air-gapped, or packaging workflows.

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
Do not open public issues for sandbox-boundary vulnerabilities.

## Acknowledgements

[containerd/nerdbox](https://github.com/containerd/nerdbox) ·
[gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock) ·
[go-erofs](https://github.com/erofs/go-erofs) ·
[go-fuse](https://github.com/hanwen/go-fuse) ·
[gVisor](https://gvisor.dev/)

Gantry is licensed under [Apache-2.0](LICENSE). Vendored code in
`third_party/` retains its original license.
