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

## Editor sidecars

For distroless, musl-minimal, or production-parity workload images, create an
explicit editor sidecar:

```console
$ gantry ssh --ide dev
$ gantry ssh --ide dev -disk-size 8192
```

`-disk-size` selects the initial private writable-layer size in MiB and only
applies when the sidecar is created. To change an existing sidecar's fixed-size
disk, delete `dev-ide` and recreate it with the desired size. `--help` reports
options without creating anything. On first creation, Gantry uses a staged
local artifact when available; otherwise it downloads the architecture-specific
`gantry-ide-image-<arch>.erofs` release asset and verifies its published SHA-256
sidecar before use.

This creates the ordinary sandbox `dev-ide`, then connects to it. The sidecar:

- uses Gantry's curated Debian/glibc editor image with bash, tar, curl, Git,
  certificates, libstdc++, and passwordless guest `sudo`;
- copies the primary's **persisted** share specifications verbatim, including
  mount paths, read-only flags, and UID/GID mappings;
- enables SSH and creates an independent writable layer;
- starts with no secrets or OAuth custody inherited from the primary;
- extends the primary egress policy with the `ide-servers` download domains;
- appears in `gantry ls` and has its own audit log.

Creation is never implicit. `ssh dev-ide.gantry` before creation tells you to
run `gantry ssh --ide dev`. A primary with no persisted shares is refused.
Re-running the command attaches idempotently. Delete the sidecar explicitly;
`gantry delete dev` warns but does not remove `dev-ide`.

### VS Code Remote SSH

Create the sidecar and install Gantry's managed `*.gantry` OpenSSH configuration:

```console
$ gantry ssh --ide dev -disk-size 8192
$ gantry ssh setup
```

Install VS Code's **Remote - SSH** extension and set server downloads to happen
on the client before upload to the sidecar:

```json
{
  "remote.SSH.localServerDownload": "always"
}
```

Open a shared project at the same container path copied from the primary
sandbox's persisted share specification:

```console
$ code --remote ssh-remote+dev-ide.gantry /workspace/project
```

For example, when a host repository is shared at its original macOS path:

```console
$ code --remote ssh-remote+codex-dev-ide.gantry /Users/example/repos/minivm
```

If the `code` shell command is not on `PATH`, run **Shell Command: Install
'code' command in PATH** from VS Code's Command Palette, or invoke the macOS
application CLI directly:

```console
$ "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code" \
    --remote ssh-remote+codex-dev-ide.gantry /Users/example/repos/minivm
```

The VS Code status bar should show `SSH: dev-ide.gantry`. Remote terminals,
tasks, and workspace extensions then run in the IDE sidecar; UI-only extensions
may still run locally. Use **Developer: Show Running Extensions** to inspect an
extension's location.

### Installing additional IDE tools

The curated sidecar grants its `gantry` user passwordless `sudo` inside the
guest, so a VS Code terminal can install packages without a separate root SSH
session:

```console
$ sudo apt-get update
$ sudo apt-get install -y jq ripgrep python3
```

These changes persist on the sidecar's private writable disk across
stop/resume and disappear when the sidecar is deleted. Passwordless `sudo`
makes workspace agents effectively root **inside this sidecar**; it grants no
host root authority, but root processes can still modify files under explicitly
shared host paths.

## Diagnostics

```console
$ gantry ssh doctor dev
$ gantry audit dev
```

Remote editor servers may additionally require a Bourne shell, tar, a writable
home, and their expected libc/libstdc++ runtime. The curated sidecar supplies
these. For VS Code, `remote.SSH.localServerDownload=always` keeps editor-server
downloads client-side and uploads them over SFTP.
