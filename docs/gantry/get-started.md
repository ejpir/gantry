# Get started with Gantry

This walkthrough creates a persistent sandbox, exposes a project directory,
runs commands, changes network access, and removes the sandbox.

## Prerequisites

- [Install Gantry](install.md).
- Choose a local project directory to share with the sandbox.

## Start a sandbox

From the project directory, start Debian with two vCPUs and 1 GiB of memory:

```console
$ cd ~/my-project
$ gantry start dev \
    -image debian:bookworm-slim \
    -cpus 2 \
    -mem 1024 \
    -share "workspace=$PWD,mount=/workspace"
```

`gantry start` creates a persistent sandbox named `dev`. The project appears
at `/workspace` inside its container. Nothing else from the host filesystem is
shared.

The image root is writable by default for a named sandbox. Gantry stores those
changes in a private ext4 layer for `dev`.

## Run commands

Open an interactive shell:

```console
$ gantry exec dev -- /bin/bash
```

Or run a single command:

```console
$ gantry exec dev -- sh -lc 'cd /workspace && make test'
```

Several terminals can execute processes in the same running sandbox at the
same time. Each process uses the OCI image's environment, user, and working
directory unless the command changes them.

## Inspect the sandbox

List saved sandboxes:

```console
$ gantry ls
NAME                 STATE      PID      SECRETS                  IMAGE
dev                  running    48122    -                        sha256-…erofs (rw)
```

Run `gantry` with no arguments in an interactive terminal, or run
`gantry tui`, to open the dashboard. It shows sandboxes, resource use,
traffic, policy rules, mounts, ports, secrets, and an in-memory packet
inspector.

## Control network access

The default policy allows public IPv4 internet access but denies local,
link-local, loopback, CGNAT, and multicast destinations. This includes the
cloud metadata range.

For a default-deny sandbox, create a policy file:

```json
{
  "default": "deny",
  "allowDomains": [
    "deb.debian.org",
    "security.debian.org"
  ]
}
```

Apply it without restarting:

```console
$ gantry net-policy set dev ./debian-policy.json
$ gantry net-policy show dev
```

See [Networking](networking.md) for CIDR rules, domain matching, proxies, and
port publishing.

## Stop and resume

Stop the VM without deleting its configuration or writable disk:

```console
$ gantry stop dev
```

Resume it later:

```console
$ gantry resume dev
```

Installed packages and changes outside the shared project survive because the
writable layer belongs to the sandbox. Host project changes also remain on the
host because the share points at the original directory.

## Clean up

Delete the sandbox when you no longer need it:

```console
$ gantry delete dev
```

Deleting removes the sandbox state directory and its private writable layer.
It does not delete shared host directories or cached OCI images.

To remove unreferenced cached images separately:

```console
$ gantry image prune
```

> [!WARNING]
> `gantry image prune` is an action command and does not accept `--help`. It
> removes every cached image digest that no saved sandbox references.

## Run a disposable command

Use one-shot execution when you do not need to preserve a sandbox:

```console
$ gantry exec -image alpine:latest -- cat /etc/os-release
```

Gantry creates a temporary sandbox using the same isolation topology, returns
the process exit code, and removes the temporary sandbox afterward.

One-shot execution does not create a persistent writable layer automatically.
Use a named sandbox when the command needs to install packages or retain
filesystem changes.
