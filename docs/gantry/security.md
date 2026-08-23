# Security

Gantry uses a microVM boundary, host-enforced shares, network policy, and
confined worker processes to reduce the impact of running untrusted or
prompt-influenced code. This page describes the boundary; it is not a claim
that Gantry is suitable for hostile public multi-tenancy.

## Threat model

Gantry is designed to limit two common failures of local automation and
coding agents:

- code inside the sandbox reads or changes host files outside explicitly
  shared directories;
- code uses network access to reach host/LAN services or exfiltrate data to
  destinations the operator did not allow.

The workload, its dependencies, the container runtime, and the guest kernel
are treated as less trusted than the host supervisor. The user who launches
Gantry remains trusted.

## Isolation boundaries

### MicroVM

Each sandbox has its own Linux kernel, RAM, vCPUs, device model, filesystem,
and network. Guest processes do not share the host kernel. Memory and CPU
limits are VM allocations rather than container accounting.

The hypervisor boundary still has attack surface: the host hypervisor API,
Gantry's VMM, and emulated virtio devices process guest-controlled input.
Gantry fuzzes and tests these paths, but a VM is not proof against every
escape.

### Host filesystem

The guest receives only pre-opened boot disks and directories named with
`-share`. Read-only shares are rejected by the host backend before a mutating
filesystem operation reaches the host.

A read-write share is deliberately writable. A compromised guest can read,
change, or delete any content within that export that the launching user can
access. Avoid sharing home directories, credential stores, Docker sockets,
or broad source roots.

The trusted supervisor itself runs as the launching user and therefore has
that user's host access. Gantry is not a privilege-separation boundary between
the user and the supervisor.

### Network

With the embedded stack, egress filtering happens on the host side of the
virtio-net link. Guest processes cannot reconfigure or bypass that enforcement
point from inside the VM.

The default permits public internet access. It is not an exfiltration-safe
default for secrets. Use a default-deny policy with explicit CIDR or domain
allowances for sensitive workloads.

DNS allowlists are name-to-address conveniences. Explicit L3/L4 rules and the
default action are the hard policy once a packet has an address. Anything a
policy allows remains a possible data destination.

Published ports create an inbound path to the guest. They bind to host
loopback by default; an explicit `0.0.0.0` bind can expose the guest service to
the LAN or beyond.

### Worker processes

In `auto` mode, Gantry attempts to separate the VMM and network data planes
from the trusted supervisor. MCP-enabled sandboxes always run MCP parsing in a
separate worker, even when OS confinement is set to `off`. Workers receive an
allowlisted descriptor table and authenticated bootstrap channels, then apply
platform confinement:

- Linux uses user, mount, and PID namespaces when available, a private root,
  capability removal, task limits, descriptor closure, `no_new_privs`,
  Landlock, and a seccomp-BPF syscall policy. VMM and MCP workers receive a
  deny-all Landlock filesystem ruleset. The network worker can read only exact
  private snapshots of `/etc/hosts`, `/etc/nsswitch.conf`, and
  `/etc/resolv.conf`; no directory subtree is allowlisted.
- macOS uses Seatbelt profiles with role-specific file and network access.
- Windows runs MCP and VMM device emulation in zero-capability AppContainers
  inside one-process Jobs. Because WHPX rejects that token, a separate narrow
  Job-confined broker owns only the partition/vCPUs and shared RAM. The network
  worker uses a separate AppContainer with an exact network-capability set;
  filesystem and exec denials are actively verified before its stack starts.

Workers probe the controls from inside the confined process. Gantry writes
the measured properties to `isolation.json`; the TUI currently shows the
configured isolation mode rather than the full per-role report. `auto` may
report degradation and continue. `required` fails startup unless
the required split-worker properties are verified. `off` disables this
defense-in-depth layer.

```console
$ gantry start sensitive -image alpine:latest \
    -process-isolation=required
```

`required` is supported only where the platform can establish and verify the
full required boundary. On Windows it requires brokered WHPX and, when
networking is enabled, the embedded network worker with a policy that does not
permit host loopback. An intentionally offline `-net=false` sandbox still uses
the split VMM. Windows AppContainer network isolation cannot support
host-loopback access or published ports without a privileged machine-wide
exemption, so strict mode rejects those options rather than weakening the
worker token.

The host MCP gateway is a separate capability-limited worker. The supervisor
keeps destination selection, DNS pinning, secret and OAuth stores, fixed guest
helper argv, and audit persistence. It relays bounded opaque streams and
releases only the credential mapped to the requested configured server ID.
Killing this worker disables MCP without killing the VM. The built-in
filesystem helper remains a separate unprivileged guest process; its `os.Root`
path containment and remaining hardening work are documented in the
[MCP worker confinement design](mcp-worker-confinement.md).

### Runtime inside the VM

`-runtime runsc` adds a gVisor boundary between the workload and the guest
kernel. It is defense in depth, not a replacement for the VM or host-side
network and share policies.

## Credentials

Registry credentials remain in the host-side image resolver. Workload secrets
are sent through an inherited stdin handshake, kept in the supervisor's
memory, and added to guest process environments. Only their names persist.

Secrets are still visible to code running as the relevant guest user and may
be inherited by child processes. A guest process can send them to any allowed
network destination or write them to a writable share. Constrain both egress
and filesystem access.

OAuth bridging opens bounded host-loopback listeners after detecting supported
agent callback URLs. Guest callback responses may redirect only to an absolute
path on the same bridge origin; external, scheme-relative, and host-local
redirect targets are rejected. Disable the bridge with `-oauth-bridge=false`
when unused.

## Local control surfaces

Sandbox control sockets and the manager socket are local, user-owned endpoints
with same-user checks or protected ACLs. They assume processes running as the
same host user are trusted. Do not forward these sockets to a network or grant
another user access to the Gantry state directory.

The manager API accepts secret names but never values, and bounds request
bodies, execution time, and captured output. Interactive CLI sessions use a
separate out-of-band exit-status channel so guest bytes cannot imitate control
messages.

Each interactive or internal command has its own guest container/PID namespace
while bind-mounting the sandbox's persistent root. Ending or killing a session
therefore removes its full process tree instead of leaving daemonized children
inside the base container. Concurrent sessions retain independent task and I/O
lifecycles.

## Integrity and persistence

Gantry's self-updater and guest-asset downloader verify release files against
SHA-256 sidecars before installation. Image cache files are content-addressed
by the selected manifest digest and published atomically after construction.

The sandbox writable layer is mutable and persists across stop/resume. Gantry
checks its association with the image to reduce accidental reuse, but it is
not a cryptographically sealed snapshot. Do not attach one writable layer to
multiple running VMs.

## Known limitations

- Gantry is experimental and has not established a stable security boundary
  for hostile public multi-tenancy.
- Windows support is experimental; strict mode does not support host-loopback
  access, published ports, `-gvproxy`, or host-path packet capture.
- Snapshots are not supported.
- The embedded guest network is IPv4-only.
- A default policy permits the public internet.
- Proxy enforcement targets direct web traffic on TCP 80/443 and UDP 443; it
  is not a universal transparent proxy.
- Writable shares and published non-loopback ports intentionally weaken the
  sandbox boundary.
- Removing a sandbox permanently removes its Gantry-managed default writable
  layer; Gantry does not provide recovery or snapshot rollback. Explicit
  `-rwlayer` paths remain caller-owned.

Report vulnerabilities privately as described in
[SECURITY.md](../../SECURITY.md).
