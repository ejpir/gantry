# Install Gantry

Install one `gantry` binary to run Linux microVM sandboxes. Docker Desktop,
Docker Engine, containerd, and libkrun are not required.

## Prerequisites

| Host | Architecture | Virtualization backend | Status |
|---|---|---|---|
| Linux | amd64 or arm64 | KVM | Supported |
| macOS 13 or later | Apple silicon | Hypervisor.framework | Supported |
| Windows | x86-64 | Windows Hypervisor Platform | Experimental |

On Linux, the current user must be able to open `/dev/kvm`. When Gantry runs
inside another VM, that environment must expose nested virtualization.

On Windows, enable Windows Hypervisor Platform and run on hardware, or in a
VM, that exposes hardware virtualization.

## Install on Linux

Download the binary for your architecture from the latest release:

```console
$ curl -L https://github.com/ejpir/gantry/releases/latest/download/gantry-linux-amd64 -o gantry
$ chmod +x gantry
$ sudo install gantry /usr/local/bin/gantry
```

Replace `amd64` with `arm64` on an Arm host.

Verify KVM access:

```console
$ test -r /dev/kvm -a -w /dev/kvm && echo "KVM is available"
```

## Install on macOS

Download the Apple silicon binary:

```console
$ curl -L https://github.com/ejpir/gantry/releases/latest/download/gantry-darwin-arm64 -o gantry
$ chmod +x gantry
$ xattr -d com.apple.quarantine gantry
$ sudo install gantry /usr/local/bin/gantry
```

## Install on Windows

From PowerShell, download the experimental x86-64 build:

```powershell
Invoke-WebRequest `
  https://github.com/ejpir/gantry/releases/latest/download/gantry-windows-amd64.exe `
  -OutFile gantry.exe
```

Place `gantry.exe` on `PATH`. Both user-owned and administrator-managed
installations can use the verified in-place updater.

## Verify the installation

```console
$ gantry version
```

Tagged builds check for newer stable releases in the background. To update
the installed binary explicitly:

```console
$ gantry update
```

Release tags are expected to be immutable. If a tag was deliberately rebuilt
while testing release infrastructure, use `gantry update --force`; the build
revision in the new binary selects a fresh guest-asset cache.

Updates and release guest assets are verified with SHA-256 sidecars before
they replace local files. Release artifacts also include Sigstore build
provenance.

## First-start downloads

On first use, Gantry downloads the matching guest kernel, system root, and
default Alpine image. Assets are cached per release **and host-binary build**
in the operating system's user cache directory. They are verified and staged
atomically. On Windows this is normally
`%LOCALAPPDATA%\gantry\assets\<version>-<build-id>`; deleting
`%USERPROFILE%\.gantry` does not remove that OS-managed asset cache.

Set `GANTRY_ARTIFACTS` to an explicit directory for local packaging,
development, or air-gapped installations:

```console
$ export GANTRY_ARTIFACTS=/opt/gantry/assets
$ gantry start dev -image alpine:latest
```

## Build from source

Gantry requires Go 1.26.6 or newer:

```console
$ go install github.com/ejpir/gantry/cmd/gantry@latest
```

From a checkout, the repository scripts build the binary and guest assets:

```console
$ ./scripts/build.sh
$ ./scripts/mkkernel.sh
$ ./scripts/mkimage.sh alpine:latest artifacts/alpine.erofs
$ go test ./...
```

After installation, [run your first sandbox](get-started.md).
