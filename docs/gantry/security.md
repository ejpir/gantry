# Security

Gantry combines a microVM, host-enforced shares and network policy, and
confined worker processes. It reduces the impact of untrusted or
prompt-influenced code, but is not presented as a hostile public multi-tenant
platform.

## Threat model

Gantry aims to stop sandbox code from:

- reading or changing host files outside explicit shares; and
- reaching host, LAN, or Internet destinations the operator did not allow.

The workload, its dependencies, guest runtime, and guest kernel are less
trusted than the host supervisor. The host user who launches Gantry remains
trusted.

## Isolation boundaries

### MicroVM

Each sandbox has its own Linux kernel, RAM, vCPUs, filesystems, devices, and
network. Guest processes do not share the host kernel.

The host hypervisor API, Gantry VMM, and virtio devices still process
adversarial guest input. A VM narrows the boundary; it does not prove that no
escape exists.

### Host filesystem

The guest receives boot disks and only directories named with `-share`.
Read-only shares are enforced by the host backend. Roots are pinned before use,
and traversal, state-directory overlap, kernel-control filesystems, and special
file creation are rejected.

A writable share is intentionally writable. Guest code can read, change, or
delete anything there that the host user can access. Share the smallest useful
directory; avoid homes, credential stores, and container-engine sockets.

Do not expose the same writable tree from multiple Gantry supervisors at once.
The supervisor itself runs as the launching user and retains that user's host
authority.

### Network

Egress filtering runs on the host side of virtio-net. The default blocks local,
LAN, metadata, and special-use destinations but allows public Internet access.
That default is not safe against exfiltration; use a default-deny policy for
sensitive data.

DNS allowlists temporarily map names to addresses. Once traffic has an IP,
explicit L3/L4 rules and the default action are authoritative. Any allowed
destination can receive data.

Published ports add inbound access. Host loopback is the default bind; an
explicit non-loopback address widens exposure.

### Worker processes

Gantry can separate VMM, network, and MCP data planes from the trusted
supervisor. Workers receive exact handles and authenticated channels, then use
platform controls:

- Linux namespaces, private roots, Landlock, seccomp, capability removal, and
  task limits;
- macOS deny-default Seatbelt profiles; and
- Windows AppContainers and one-process Jobs, with a narrow WHPX broker where
  needed.

Workers probe their effective controls and write results to `isolation.json`.
`auto` may continue with reported degradation, `required` fails unless required
properties are verified, and `off` disables this defense-in-depth layer.

```console
$ gantry start sensitive -image alpine:latest -process-isolation=required
```

On Windows, strict mode does not support host-loopback network access or
published ports. An offline `-net=false` sandbox remains compatible.

MCP parsing always stays in a separate worker when enabled. A configured MCP
server receives its own credential by design; response redaction cannot stop a
malicious server from transforming it. See
[MCP confinement](mcp-worker-confinement.md).

### Runtime inside the VM

`-runtime runsc` adds gVisor between the workload and guest kernel. It is
defense in depth, not a replacement for the VM or host-side policies.

Workload procfs permits nested user/PID-namespace tools such as bubblewrap. It
still exposes only guest-kernel and workload-namespace state, not host
processes or the host kernel.

## Credentials

Registry credentials stay in the host image resolver. Ordinary workload
secrets stay in supervisor memory and enter selected guest process
environments; only names and source references persist.

Guest code can read an injected secret and send it through any allowed network,
MCP, or writable-share path. Use narrow egress and filesystem grants.

File-backed sources must be existing single-link regular files reached through
clean, absolute, symlink-free paths. Sources inside or aliased beneath writable
shares are rejected. Command-backed sources are disabled.

Bound secrets remain host-side until the credential broker releases one for an
allowed destination. OAuth custody keeps refresh tokens host-side but may
release current access tokens to configured adapters. Already delivered values
cannot be recalled.

The OAuth callback bridge accepts only bounded OAuth-shaped loopback callbacks;
the guest still validates state and PKCE. The host does not render guest
responses. Disable it when unused.

See [Host shares and secrets](shares-secrets.md), [OAuth](oauth.md), and
[Architecture](architecture.md#host-capability-bridges) for operational and
protocol details.

## Local control surfaces

Sandbox and manager sockets are private same-user endpoints, using peer checks
or protected Windows ACLs. Same-host-user processes are trusted. Do not forward
these sockets or grant another account access to Gantry state.

The manager API accepts secret names, not values, and bounds requests, time,
and output. Interactive execution carries exit status outside guest output, so
guest bytes cannot forge control state.

## Integrity and persistence

Release updates and guest assets are checked against SHA-256 sidecars. OCI
cache entries are content-addressed and atomically published.

Writable layers persist but are not sealed snapshots. Never attach one to two
running VMs. Export requires a stopped sandbox and includes every guest-created
file in the workload layer, including credentials or history. Review archives
before sharing.

Organization audit logs are bounded and best-effort, not tamper-resistant
compliance storage.

## Known limitations

- Gantry is experimental and not a proven hostile multi-tenant boundary.
- Windows support is experimental.
- Snapshots and rollback are unsupported; OCI export requires a stopped
  sandbox.
- Guest networking is IPv4-only.
- Public Internet is allowed by default.
- Proxy enforcement covers direct web traffic, not every protocol.
- Writable shares and non-loopback published ports intentionally weaken
  isolation.
- Deleting a sandbox permanently removes Gantry-managed writable layers.

Report vulnerabilities privately as described in
[SECURITY.md](../../SECURITY.md).
