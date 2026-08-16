# Architecture

This page explains how Gantry turns an OCI image and a small set of host
capabilities into a running microVM sandbox. For the security properties and
limitations of these boundaries, see [Security](security.md).

## System overview

One named sandbox has one trusted supervisor and one Linux microVM. In the
default isolation mode, separate workers own the hypervisor/device model and
the userspace network data plane where the host supports the required
controls.

```text
                         host

  gantry CLI / TUI / manager API
                 │
                 │ same-user local control
                 ▼
  ┌───────────────────────────────────────────────┐
  │ sandbox supervisor                            │
  │ lifecycle • config • secrets • ctl.sock       │
  │ guest RPC bridge • share roots • host ports   │
  └───────────┬───────────────────┬───────────────┘
              │ authenticated     │ authenticated
              │ worker channels   │ frame/control channels
              ▼                   ▼
  ┌──────────────────────┐   ┌──────────────────────┐
  │ VMM worker           │   │ network worker       │
  │ hypervisor • RAM     │   │ policy • NAT • DNS   │
  │ virtio devices       │   │ forwards • traffic   │
  └──────────┬───────────┘   └──────────┬───────────┘
             │ virtio                   │ host sockets
             ▼                          ▼
  ┌──────────────────────────────┐   public network / proxy
  │ Linux microVM                │
  │ vminitd                      │
  │   └─ crun or runsc           │
  │       └─ OCI workload        │
  └──────────────────────────────┘
```

If split workers are unavailable in `auto` mode, Gantry records the degraded
topology and may fall back. `required` fails the start instead. `off` runs a
monolithic process. Effective, verified state is written to `isolation.json`;
the configured mode alone is not treated as proof.

## Host components

### CLI and dashboard

The `gantry` binary contains the command-line client, terminal dashboard,
manager service, supervisor, network stack, and VMM. Hidden worker roles
re-execute the same binary with inherited, authenticated channels.

The ordinary command paths are:

- `start` resolves configuration and launches a persistent supervisor.
- `exec <name>` connects to that supervisor's local session broker.
- one-shot `exec` creates a randomly named transient sandbox, runs one
  session, and deletes it.
- `tui` uses the same local lifecycle and control surfaces as the CLI.
- `serve` provides a structured local HTTP API and delegates lifecycle work
  to the same implementation.

### Sandbox supervisor

The supervisor is the trusted host control plane for one sandbox. It owns:

- durable `sandbox.json` configuration and the sandbox lifetime lock;
- the in-memory secret map;
- local control listeners and session multiplexing;
- opened boot assets and writable disks before capabilities are delegated;
- host share roots and share admission policy;
- port and policy mutations, traffic snapshots, and graceful shutdown;
- the persistent guest ttrpc connection over virtio-vsock.

The supervisor runs with the privileges of the user who launched Gantry. It
does not run as a system daemon.

### VMM worker

The VMM worker owns guest RAM, the platform hypervisor, virtual CPUs, and the
virtio device model. The supervisor passes pre-opened files and authenticated
channels, so a confined worker does not need general host-path access.

The VMM uses:

| Host | Backend |
|---|---|
| Linux | KVM |
| Apple silicon macOS | Hypervisor.framework |
| Windows x86-64 | Windows Hypervisor Platform |

Gantry implements the VM and its virtio devices in Go; it does not wrap QEMU
or libkrun.

### Network worker

The network worker runs the userspace IPv4 stack, DNS gateway, egress policy,
host-to-guest forwarding, and traffic accounting. Frames leaving the VM cross
the policy point before they reach a host socket. DNS replies cross it on the
way back so the policy can maintain bounded, TTL-limited domain allowances.

The network worker necessarily retains restricted stream and datagram socket
creation authority. It does not receive secrets, writable disks, guest RAM,
or host share roots.

An explicit `-gvproxy` selects an external backend instead. Live policy,
traffic inspection, proxy enforcement, and built-in port publishing require
the embedded stack.

## Guest components

The guest boots a Gantry kernel and a small EROFS system root derived from
containerd/nerdbox. `vminitd` configures devices and the network, provides
mount, bundle, task, and stream services over ttrpc, and starts the selected
OCI runtime.

`crun` is the default runtime. `runsc` runs a gVisor sandbox inside the VM and
uses compatible guest assets.

For a persistent sandbox, Gantry keeps one long-lived workload container.
Each `gantry exec <name>` creates an OCI exec process in that container. The
supervisor multiplexes concurrent sessions over the VM's single ttrpc
dial-back connection, while separate virtio-vsock streams carry their I/O.

## Boot flow

```text
start request
    │
    ├─ validate resources, paths, shares, policy, and proxy
    ├─ locate or download verified guest assets
    ├─ resolve OCI image for the guest architecture
    ├─ build/reuse digest-addressed EROFS
    ├─ create and pair a private ext4 writable layer
    ├─ write durable sandbox.json
    └─ launch supervisor
           │
           ├─ load secrets from the inherited stdin handshake
           ├─ start network and share services
           ├─ open kernel, rootfs, image, and writable disk
           ├─ start and confine workers
           ├─ boot virtual CPUs
           ├─ accept the guest ttrpc dial-back
           ├─ start the same-user ctl.sock broker
           └─ publish readiness
```

The parent `start` command returns only after both guest RPC and `ctl.sock` can
accept work. Boot inputs are opened before worker confinement, which prevents
a path from being exchanged between validation and use.

## Filesystems and persistence

The guest receives several block-backed filesystems:

- a read-only Gantry system root containing `vminitd` and guest tooling;
- a read-only flattened OCI image, or a native EROFS layer set;
- an optional private ext4 writable layer used as the overlay upper layer.

OCI image cache entries are immutable and shared between sandboxes by digest.
Writable ext4 layers are private and must not be shared by running VMs.

Host directories use a single multiplexed virtio-fs share hub. Each admitted
tag appears in the guest namespace and is bind-mounted into the container at
its selected path. The supervisor retains the host roots and applies
read-only and path-confinement policy. On supported Unix hosts, the split VMM
uses shared guest RAM and vhost-style doorbells so the VMM worker does not
receive host share roots; other paths use an authenticated request relay.

There is no filesystem sync or private checkout layer: host-share changes are
changes to the original host directory.

## Network flow

```text
guest process
    │
    ▼
virtio-net
    │ Ethernet frames
    ▼
egress policy + traffic recorder
    │ allowed frames only
    ▼
userspace NAT / DNS / forwarder
    │
    ▼
host sockets → destination or upstream proxy
```

The default local-network wall is independent of an allow-by-default public
internet posture. Published ports travel in the opposite direction: a
specific host listener forwards to the fixed guest address and selected port.

## Local control and execution

Each persistent sandbox exposes `ctl.sock` inside its private state directory.
On Unix, the broker validates peer credentials; Windows uses a protected local
endpoint. A terminal session uses two channels:

1. A bounded JSON control channel carries the versioned exit event.
2. A data channel becomes a raw standard-input/output byte stream after its
   bounded JSON handshake.

Keeping the exit status out of the byte stream means guest output cannot forge
process state. The manager API uses the same broker with explicit timeout and
output-size bounds.

## On-disk state

The default layout is:

```text
<user-cache>/gantry/assets/<version>/
    └── verified release kernel, system root, and default image

~/.gantry/
├── credentials.json
├── images/
│   ├── index.json
│   ├── sha256-<digest>.erofs
│   └── sha256-<digest>.json
├── rwlayers/
│   ├── <name>.ext4
│   └── <name>.ext4.image
└── sandboxes/<name>/
    ├── sandbox.json
    ├── isolation.json
    ├── network-traffic.json
    ├── console.log
    ├── daemon.log
    ├── worker-net.log
    ├── worker-vmm.log
    └── runtime locks, sockets, and readiness files
```

Secret values do not appear in this layout. A stop removes transient runtime
sockets and processes but preserves configuration and disk state. Delete also
removes the named sandbox's Gantry-managed default writable layer; a custom
`-rwlayer` remains caller-owned.
