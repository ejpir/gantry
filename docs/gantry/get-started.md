# Get started with Gantry

This walkthrough creates a sandbox, shares a project, runs commands, changes
network access, and cleans up.

## Start a sandbox

[Install Gantry](install.md), then run this from a project directory:

```console
$ gantry start dev \
    -image debian:bookworm-slim \
    -cpus 2 -mem 1024 \
    -share "workspace=$PWD,mount=/workspace"
```

The named sandbox `dev` is persistent. Its image root is writable, and the
shared project appears at `/workspace`. No other host directory is shared.

## Run commands

Open a shell:

```console
$ gantry exec dev -- /bin/bash
```

Or run one command:

```console
$ gantry exec dev -- sh -lc 'cd /workspace && make test'
```

Several terminals can use the same running sandbox. Commands inherit the OCI
image's user, environment, and working directory.

## Inspect it

```console
$ gantry ls
```

Run `gantry` in an interactive terminal, or `gantry tui`, to open the terminal
dashboard. It shows sandboxes, resources, network activity, shares, ports,
secrets, and MCP servers.

## Limit network access

Networking allows public IPv4 by default but blocks host, LAN, metadata, and
other local or special-use addresses. To allow only selected domains, save:

```json
{
  "default": "deny",
  "allowDomains": ["deb.debian.org", "security.debian.org"]
}
```

Then apply it:

```console
$ gantry net-policy set dev ./debian-policy.json
$ gantry net-policy show dev
```

See [Networking](networking.md) for policy rules, proxies, port publishing, and
traffic inspection.

## Stop, resume, and delete

```console
$ gantry stop dev
$ gantry resume dev
$ gantry delete dev
```

Stop preserves the sandbox's configuration and writable disk. Delete removes
them, but never deletes shared host directories or cached OCI images.

Remove unreferenced images separately:

```console
$ gantry image prune
```

## Run one disposable command

When persistence is unnecessary, omit the sandbox name:

```console
$ gantry exec -image alpine:latest -- cat /etc/os-release
```

Gantry creates a temporary microVM, returns the command's exit code, and then
removes it. Use a named sandbox when you need to keep installed packages or
filesystem changes.

Next, see [Everyday usage](usage.md) or the [CLI reference](cli-reference.md).
