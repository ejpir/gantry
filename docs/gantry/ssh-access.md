# SSH access

Gantry can terminate the SSH protocol on the host and run each session inside
a sandbox. It never starts `sshd` in the guest and never publishes an SSH TCP
port. Access uses `ssh.sock` in the sandbox's private state directory, so its
local authentication boundary is the same as `gantry exec`.

## Enable and connect

SSH is opt-in when the sandbox is created:

```console
$ gantry start dev -ssh -image debian:bookworm-slim
$ gantry ssh dev
$ gantry ssh dev -- uname -a
$ gantry ssh root@dev -- id
```

`gantry ssh` invokes the stock OpenSSH client with a Gantry `ProxyCommand` and
`KnownHostsCommand`; it does not require permanent client configuration. The
username defaults to the OCI image user. An explicitly selected guest user must
exist in `/etc/passwd`. Root is allowed, matching `gantry exec` authority.

A stopped sandbox or one created without `-ssh` is refused without falling
back to another transport.

## Permanent `*.gantry` hostnames

OpenSSH 8.4 or newer can use Gantry's managed wildcard configuration:

```console
$ gantry ssh setup
$ ssh dev.gantry
$ ssh dev.gantry hostname
```

Setup adds one `Include` to `~/.ssh/config`. The managed, marker-delimited
`Host *.gantry` block lives under `~/.gantry/ssh/config`; writes are locked and
atomic. Gantry refuses an incomplete marker block rather than rewriting a
possibly hand-edited file.

Remove only Gantry-managed configuration with:

```console
$ gantry ssh setup --remove
```

The install-wide Ed25519 host key is stored at
`~/.gantry/ssh/host_ed25519` with mode 0600. A corrupt key fails loudly. To
rotate it, stop SSH-enabled sandboxes, delete that file, and reconnect.

## SFTP, SCP, rsync, and forwarding

The gateway supports normal session, PTY, resize, and SFTP requests:

```console
$ sftp dev.gantry
$ scp -O ./file dev.gantry:/workspace/
$ rsync -av ./src/ dev.gantry:/workspace/src/
```

SFTP runs as the selected guest user and therefore follows guest POSIX
permissions.

Local forwarding is restricted to guest loopback:

```console
$ ssh -L 8080:127.0.0.1:3000 dev.gantry
```

Targets other than `127.0.0.1` or `::1` are refused. Remote forwarding,
agent forwarding, password authentication, and public-key authentication are
not supported. `NoClientAuth` is deliberate: the private local socket and its
same-user check are the authentication boundary.

Client environment requests are limited to `TERM`, `LANG`, `LC_*`,
`COLORTERM`, and `TERM_PROGRAM`. Drops and all session/channel/forward/SFTP
lifecycle events are recorded by `gantry audit NAME` and in `audit.log`.

## Remote editors

Enable SSH when creating a development sandbox, or add it to a running VM:

```console
$ gantry start dev -ssh
$ gantry configure dev -ssh
$ gantry ssh setup
```

VS Code Remote SSH needs a Bourne shell, tar, a writable home, and a compatible
libc/libstdc++ runtime in the selected image. `gantry ssh doctor dev` reports
these requirements. Setting `remote.SSH.localServerDownload=always` makes VS
Code download its server on the client and upload it over SFTP.

Open a shared project at its guest path:

```console
$ code --remote ssh-remote+dev.gantry /workspace/project
```

Remote terminals, tasks, and workspace extensions run inside `dev`; UI-only
extensions may still run locally.

## Dev Containers

Dev Containers run as nested OCI containers inside the same sandbox VM. Create
a development sandbox with the curated Podman image and resource defaults:

```console
$ gantry start dev -ssh -devcontainers
```

Unless explicitly overridden, `-devcontainers` selects 4096 MiB RAM, 4 vCPUs
(capped by the host), and a 32768 MiB sparse writable disk. Each value remains
independently configurable:

```console
$ gantry start dev -ssh -devcontainers -mem 8192 -cpus 6 -disk-size 49152
```

Enable the profile later without rebooting an already-running VM:

```console
$ gantry configure dev -ssh -devcontainers
```

SSH and Dev Containers apply immediately to newly created sessions. Memory,
CPU, and process-isolation changes made with `gantry configure` are persisted
for the next VM start. The writable disk size is selected when the sandbox is
created. Enabling the profile later does not replace the sandbox image: a
custom image must already provide Podman and its userspace dependencies;
`gantry ssh doctor dev` verifies them.

After connecting with Remote SSH, install VS Code's **Dev Containers**
extension and run **Dev Containers: Reopen in Container**. The curated image
provides `/usr/local/bin/docker`, a Docker-compatible wrapper around rootful
Podman. No host Docker socket or TCP container-engine endpoint is exposed.

The profile adds only the outer OCI facilities needed by the nested runtime:
`/dev/fuse`, `/dev/net/tun`, a read-only cgroup2 view, shared root mount
propagation, and the mount/network administration capabilities used by inner
`crun`. Nested cgroup management is disabled and Podman defaults to
`slirp4netns`. Gantry's VM allocation and network worker remain the resource
and egress boundaries.

Nested images, containers, and volumes consume the sandbox's private writable
disk. Inner containers share the VM's memory and CPU allocation. Host bind
mounts are limited to paths already shared into the sandbox. A nested-runtime
escape can therefore control the sandbox VM and its shared files, but does not
escape the microVM or gain an undeclared host path.

### Installing additional tools

The curated image grants its `gantry` user passwordless `sudo`, so tools can be
installed from an SSH terminal:

```console
$ sudo apt-get update
$ sudo apt-get install -y jq ripgrep python3
```

Changes persist on the sandbox's private writable disk until it is deleted.

## Diagnostics

```console
$ gantry ssh doctor dev
$ gantry audit dev
```

Remote editor servers may additionally require a Bourne shell, tar, a writable
home, and their expected libc/libstdc++ runtime. The curated development image
supplies these. For VS Code, `remote.SSH.localServerDownload=always` keeps editor-server
downloads client-side and uploads them over SFTP.
