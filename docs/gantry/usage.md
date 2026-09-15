# Use Gantry

This page covers everyday sandbox operations. Use `gantry COMMAND --help` for
all flags.

## Persistent and one-shot sandboxes

A named sandbox keeps its configuration and writable disk:

```console
$ gantry start dev -image python:3.12
$ gantry exec dev -- python --version
$ gantry stop dev
$ gantry resume dev
$ gantry delete dev
```

A one-shot sandbox exists for one command:

```console
$ gantry exec -image python:3.12 -- python --version
```

With no command, Gantry uses the image entrypoint and command, then `/bin/sh`
as a fallback.

Sandbox names may contain letters, digits, `.`, `_`, and `-`, up to 64
characters. `.` and `..` are invalid.

## Configure resources

Set resources when creating a sandbox:

```console
$ gantry start build -image golang:latest -cpus 4 -mem 4096 -disk-size 4096
```

- `-cpus` sets virtual CPUs.
- `-mem` sets memory in MiB.
- `-disk-size` sets the initial private writable-disk size.
- `-process-isolation` selects `auto`, `required`, or `off`.

Save CPU, memory, process-isolation, SSH, or Dev Containers changes later with
`gantry configure`. Some changes require a stop and resume.

## Choose a runtime

Gantry uses `crun` in the guest by default:

```console
$ gantry start dev -image alpine:latest -runtime crun
```

Use `-runtime runsc` to add a gVisor boundary inside the microVM. Gantry
downloads matching guest assets when needed.

## Control persistence

Named sandboxes receive a private writable ext4 layer by default. Disable it
for a read-only container root:

```console
$ gantry start readonly -image alpine:latest -rw=false
```

Host shares require a writable root so the guest can create mount points.
Writable layers must not be attached to two running VMs. Snapshots are not
supported.

## Use the terminal dashboard

Run:

```console
$ gantry tui
```

The dashboard can create and manage sandboxes, images, network rules, traffic,
packet capture, shares, ports, secrets, and MCP servers. Press `?` for keys.

Useful controls:

- `/` filters sandbox-scoped views by sandbox name.
- `S` chooses a sort field; selecting a column sorts by that column.
- `n` opens the create flow.
- `A` opens the audit view.

Sorting and filtering affect only the display.

## Find local state

Persistent state is under `~/.gantry` by default. `GANTRY_HOME` changes the
sandbox-state root, and `GANTRY_IMAGES` changes the image cache. These
overrides are mainly for testing and managed installations.

See [Architecture](architecture.md#on-disk-state) for the complete layout and
[CLI reference](cli-reference.md) for every command.
