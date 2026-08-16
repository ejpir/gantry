# Gantry

Gantry runs OCI images in lightweight Linux microVMs. Each sandbox has a
private guest kernel, container root, writable disk, and network. A sandbox
can see host directories only when you share them explicitly.

Gantry is a standalone binary. It does not require Docker, containerd, or a
host daemon.

> [!NOTE]
> Gantry is experimental. Linux and Apple silicon macOS are supported.
> Windows support is experimental.

## Get started

[Install Gantry](install.md), then start a persistent sandbox:

```console
$ gantry start dev -image debian:bookworm-slim
$ gantry exec dev -- /bin/bash
```

Or run a command in a disposable sandbox:

```console
$ gantry exec -image alpine:latest -- uname -a
```

The first start downloads and verifies the guest kernel, system root, and
default image. Gantry pulls OCI images directly and caches the flattened
filesystem by digest.

## Learn more

- [Get started](get-started.md) — create a sandbox, run commands, inspect it,
  and clean up.
- [Usage](usage.md) — day-to-day lifecycle, resources, runtimes, the terminal
  dashboard, and persistence.
- [Images](images.md) — supported image sources, caching, configuration, and
  registry credentials.
- [Networking](networking.md) — egress policy, DNS allowlists, port
  publishing, proxies, and traffic inspection.
- [Host shares and secrets](shares-secrets.md) — expose selected directories,
  map ownership, and inject credentials without putting values in argv.
- [Coding agents](coding-agents.md) — isolate an agent and run Pi in a
  project sandbox.
- [Manager API](manager-api.md) — automate local sandbox lifecycle over an
  authenticated Unix socket.
- [Architecture](architecture.md) — supervisor, workers, microVM, storage,
  networking, and request flows.
- [Security](security.md) — trust boundaries, isolation controls, and known
  limitations.
- [CLI reference](cli-reference.md) — commands, flags, and accepted value
  formats.
- [Troubleshooting](troubleshooting.md) — common startup, image, network, and
  recovery problems.

Run `gantry --help`, or `gantry start --help`, for the reference built into
your installed version.

