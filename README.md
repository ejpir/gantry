# gantry: microVM sandboxes

**gantry** runs Linux OCI workloads inside lightweight VMs. It is a standalone
Go VMM and CLI, not a containerd runtime shim. It uses KVM on Linux and
Hypervisor.framework on Apple Silicon macOS. Windows WHPX support is
experimental.

Gantry reuses the guest kernel, EROFS rootfs, `vminitd`, and task APIs from
[nerdbox](https://github.com/containerd/nerdbox), but does not require Docker,
containerd, or libkrun.

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
| Windows x86-64 | WHPX | Cross-build only; not boot-verified |

## Getting started

Requirements:

- Go 1.26.5+
- A matching kernel and guest rootfs in `artifacts/`:

  ```text
  artifacts/nerdbox-kernel-arm64
  artifacts/nerdbox-rootfs-arm64.erofs
  artifacts/nerdbox-kernel-x86_64
  artifacts/nerdbox-rootfs-x86_64.erofs
  ```

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
$G delete dev
```

On macOS, use the signing wrapper:

```sh
./scripts/run-macos.sh exec -image alpine:latest -- /bin/sh
./scripts/run-macos.sh start dev -image debian:bookworm-slim
./artifacts/gantry-darwin-arm64 exec dev -- /bin/sh
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
./scripts/mkkernel-4k.sh                 # arm64 only
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
$G run -kernel artifacts/nerdbox-kernel-arm64 \
  -initrd artifacts/initramfs-shell.cpio.gz
./scripts/run-qemu-test.sh       # no KVM required
./scripts/run-qemu-shell.sh
```

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

- Windows boot and virtio-fs are not verified.
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
