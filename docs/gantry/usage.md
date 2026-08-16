# Use Gantry

Use this page as a command-oriented guide to everyday sandbox operations.

## Choose persistent or one-shot execution

A named sandbox keeps its writable disk and configuration between starts:

```console
$ gantry start dev -image python:3.12
$ gantry exec dev -- python --version
$ gantry stop dev
$ gantry resume dev
```

A one-shot sandbox exists only for one command:

```console
$ gantry exec -image python:3.12 -- python --version
```

Both modes use the same supervisor, worker, network-policy, share, and guest
execution paths.

## Start, stop, and delete

The basic lifecycle is:

```console
$ gantry start dev -image alpine:latest
$ gantry ls
$ gantry stop dev
$ gantry resume dev
$ gantry delete dev
```

`stop` asks the guest to sync, flushes devices, and preserves `sandbox.json`
and the writable disk. `resume` boots the saved configuration. `delete` stops
a running sandbox, removes its saved state, and removes its Gantry-managed
default writable layer. An explicitly supplied `-rwlayer` remains at its
original path.

Sandbox names may contain letters, digits, `.`, `_`, and `-`, and may be at
most 64 characters. `.` and `..` are not valid names.

## Execute processes

With no explicit command, Gantry uses the OCI image's entrypoint and command,
falling back to `/bin/sh`:

```console
$ gantry exec -image alpine:latest
```

Pass a command after `--`:

```console
$ gantry exec -image debian:bookworm-slim -- apt-cache policy
$ gantry exec dev -- /usr/bin/env
```

Named attach mode does not accept execution flags. Terminal detection, window
size, standard input/output, signals, and the guest process exit code are
relayed through the sandbox's local control broker.

## Configure resources

Set resources when creating a sandbox:

```console
$ gantry start build -image golang:latest -cpus 4 -mem 4096 -disk-size 4096
```

- `-cpus` sets the number of virtual CPUs, up to the limit reported in
  `gantry start --help` for the current host.
- `-mem` sets guest memory in MiB.
- `-disk-size` sets the initial private writable-layer size in MiB. It is used
  only when Gantry creates that layer.

The dashboard can save CPU, memory, and process-isolation changes for the next
boot. Stop and resume the sandbox to apply them.

## Choose a guest runtime

Gantry uses `crun` in the guest by default:

```console
$ gantry start dev -image alpine:latest -runtime crun
```

Use gVisor inside the VM for an additional workload boundary:

```console
$ gantry start dev-gvisor -image alpine:latest -runtime runsc
```

`runsc` selects matching gVisor guest assets. On Apple silicon it also needs
the 4 KiB-page Gantry kernel. The first start downloads the matching release
assets when available.

## Control the writable root

Named sandboxes receive a private writable ext4 layer by default. To run with
a read-only container root:

```console
$ gantry start readonly -image alpine:latest -rw=false
```

Host shares require a writable container root because the guest must create
the mount points. A writable layer must never be attached to two running VMs.
Gantry's per-sandbox default avoids that unsafe sharing.

Snapshots are not supported.

## Open the terminal dashboard

Run Gantry without a subcommand in an interactive terminal:

```console
$ gantry
```

`gantry tui` opens the same dashboard explicitly. From it you can create,
start, stop, enter, edit, and remove sandboxes; inspect storage and isolation;
and manage network rules, traffic, packet capture, shares, ports, and secrets.
Press `?` in the dashboard for its current key bindings.

## Inspect local state

By default, persistent state is under `~/.gantry`:

```text
~/.gantry/
├── sandboxes/<name>/    configuration, logs, sockets, runtime state
├── rwlayers/            private persistent ext4 disks
├── images/              digest-addressed flattened OCI images
└── credentials.json     Gantry registry credentials, when no helper is used
```

Set `GANTRY_HOME` to override the sandbox-state root, or `GANTRY_IMAGES` to
override the image cache. These overrides are primarily useful for testing
and controlled packaging.

See [Architecture](architecture.md) for the complete state and process model.
