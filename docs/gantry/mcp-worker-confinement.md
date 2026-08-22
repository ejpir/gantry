# MCP Worker and Filesystem Confinement Plan

**Status:** proposed; not implemented. The current host MCP gateway runs in the
per-sandbox supervisor. The built-in filesystem server already runs as a
separate, unprivileged process inside the Linux guest, but its `os.Root` is
path containment rather than a complete process sandbox.

This plan separates those two concerns:

1. move the host MCP protocol and remote-HTTP attack surface into a confined
   `_mcp-worker`; and
2. harden the existing in-guest filesystem helper without moving host paths or
   share roots into a host worker.

The worker architecture follows the existing
[VMM and network worker model](architecture.md#host-components): one
executable, a role-specific capability set, authenticated bootstrap channels,
platform [worker confinement](security.md#worker-processes), and in-worker
verification reported through `isolation.json`.

## Decision

Move `mcpgw` out of the trusted supervisor and into one worker per sandbox when
MCP is enabled. Keep the secret store, OAuth refresh tokens, destination
validation, lifecycle state, share roots, and arbitrary guest execution out of
that worker.

Do **not** move `gantry-guest mcp-serve filesystem` onto the host. A filesystem
server needs the guest's mount namespace and guest-visible share paths. Running
it on the host would either produce the wrong filesystem view or delegate host
filesystem authority to a parser reachable from the guest.

A process split by itself is only a crash boundary. The MCP split ships only
with a capability-limited channel design and honest confinement reporting; an
unconstrained sibling process is not described as a security boundary.

## Why split the host gateway

The current supervisor owns high-value state:

- the complete per-sandbox secret store and OAuth custody registry;
- host share roots, writable disks, control sockets, and lifecycle state;
- the persistent guest RPC connection; and
- host port and network-policy control.

The same address space currently parses guest-controlled JSON-RPC, remote HTTP
headers, JSON, and SSE. A memory-safety or runtime bug in that path would land
inside the trusted control plane. A confined worker limits that compromise to
the MCP capabilities deliberately delegated to one sandbox.

The split does not make MCP policy cryptographically trustworthy after
arbitrary code execution in the worker. Like compromise of the network policy
worker, compromise of the MCP policy point can bypass policy implemented by
that worker. The objective is to keep that compromise away from unrelated
host files, processes, networks, sandboxes, and credentials.

## Threat model

### Adversaries

Assume either of these can send malicious input:

- a prompt-injected workload with complete control of the guest MCP connection;
- a configured remote MCP server, including its HTTP and SSE responses; or
- a local MCP server that emits malformed or adversarial stdio frames.

Also assume a successful parser exploit gives arbitrary code execution in the
MCP worker, including access to its memory and every delegated descriptor.

### Required containment

A compromised MCP worker must not be able to:

- read or write arbitrary host paths;
- inspect `sandbox.json`, `oauth-tokens.json`, host share roots, SSH material,
  registry credentials, or other sandbox state;
- retrieve an unreferenced secret or any OAuth refresh token;
- create arbitrary Internet, LAN, loopback, Unix-socket, or named-pipe
  connections;
- select an IP address, hostname, URL, credential, or local-server argv for a
  broker request;
- execute another program or re-exec a hidden Gantry role;
- enumerate, inspect, or signal the supervisor or another worker;
- inherit ambient descriptors from the supervisor;
- address another sandbox's MCP listener or capability channel; or
- survive the supervisor that created it.

The supervisor must continue to enforce session and spawn limits even if the
worker ignores its own limits.

### Accepted residual risk

The worker must use the credentials delegated to configured MCP upstreams.
Arbitrary code execution in it can therefore steal or misuse the current
access token or API key for those upstreams and can return that value to its
connected guest. The worker receives no refresh token and no unrelated secret,
so the loss is scoped but real.

A compromised worker can also:

- call disallowed tools at an already configured upstream;
- send arbitrary data to an already configured origin through a brokered
  connection;
- read or corrupt MCP payloads in its active sessions; and
- deny MCP service by hanging, exhausting its limits, or exiting.

Eliminating the first two residuals requires a second, independently trusted
MCP policy/credential transport that understands enough of the protocol to
re-enforce every call. That is not part of the initial split. The boundary is
host-compromise reduction, not preservation of tool policy after worker RCE.

The configured upstream itself receives its credential and requested data by
design. Tool descriptions and results remain prompt-injection inputs.

## Target topology

```text
                                      configured remote origin
                                                 ^
                                                 | connected TCP fd only
                                                 |
 trusted sandbox supervisor                     |
+--------------------------------------+         |
| config + immutable server map        |   +-----+----------------------+
| secret store + OAuth refresh tokens  |   | confined _mcp-worker       |
| SSRF validation + DNS + dial broker -+-->| MCP/JSON/SSE parsing       |
| fixed local-server spawn broker -----+-->| tool policy + ID mapping   |
| structured audit sink                |   | HTTP/TLS + redaction       |
| worker lifecycle + hard limits       |   | no path/net/exec authority |
+------------------+-------------------+   +-----------+----------------+
                   | accepted guest fd                    |
                   | and fixed guest stdio                | MCP frames
                   | capabilities                         |
                   v                                      v
        guest filesystem helper                    guest mcp-proxy
        (separate unprivileged process)             over virtio-vsock
```

The supervisor may accept a local MCP connection, but it does not read MCP
bytes. It transfers the connected descriptor to the worker over the existing
authenticated descriptor-channel pattern. This keeps the guest parser out of
the supervisor while avoiding `accept` authority in the worker.

## Responsibility split

| Responsibility | Owner |
| --- | --- |
| Persist and validate MCP configuration | Supervisor |
| Hold secret sources and OAuth refresh tokens | Supervisor |
| Resolve a configured server name to an immutable origin | Supervisor |
| Resolve, validate, and pin a destination address | Supervisor dial broker |
| Parse guest MCP, remote JSON/SSE, and local stdio | MCP worker |
| Enforce normal tool allow/deny policy | MCP worker |
| Hold a current, scoped MCP access credential | MCP worker, on demand |
| Inject and redact that scoped credential | MCP worker |
| Start the built-in guest helper with fixed argv/root/user | Supervisor spawn broker |
| Open arbitrary guest processes | Neither; the MCP channel cannot request this |
| Persist audit events and worker lifecycle evidence | Supervisor |
| Access the guest-visible filesystem | In-guest helper only |

Supervisor-side capability events such as credential release, origin dial, and
local-helper spawn are authoritative audit facts. Per-tool decisions originate
in the worker and are useful operational evidence, but are not trustworthy
after worker compromise.

## Capability channels

Use separate authenticated channels for control and descriptor transfer, as
with the VMM and network workers. Data from the guest must never share framing
with trusted capability commands. Every request and reply is length-bounded,
deadline-aware, and concurrency-limited in the supervisor. An unknown method,
malformed frame, nonce failure, or descriptor-token mismatch is a fatal worker
protocol violation, not a recoverable error the worker can repeat indefinitely.

### Bootstrap channel

The supervisor sends a bounded configuration containing only:

- a sandbox-scoped nonce and protocol version;
- server IDs, normalized origins, and tool policies;
- credential reference **names**, never source definitions or values;
- the built-in local server ID and display metadata; and
- resource limits.

The worker must reject duplicate server IDs, unknown fields, unsupported
versions, malformed policies, oversized bootstrap data, and a nonce mismatch.
The immutable bootstrap is the worker's complete server namespace for its
lifetime.

### Guest-session descriptors

The supervisor accepts the per-sandbox Unix socket or Windows endpoint,
applies a global session limit, and sends the connected stream with a random
one-use descriptor token. The worker matches that token to a bounded control
message before consuming the stream. Unknown, duplicate, or expired tokens are
closed.

The supervisor must not copy MCP payload bytes. Closing either side or killing
the worker must reliably close all active guest streams.

### Origin dial broker

The worker requests a connection using only a configured `serverID`. It cannot
supply a hostname, address, port, scheme, path, or proxy target.

For each request the supervisor:

1. looks up the immutable server configuration;
2. applies the existing HTTPS/loopback rules;
3. resolves the configured hostname;
4. rejects private, link-local, CGNAT, metadata, multicast, documentation, and
   otherwise non-public addresses, except for the explicit loopback
   development case;
5. dials the validated address itself, preserving DNS pinning; and
6. transfers only the connected stream descriptor.

TLS remains in the worker so remote protocol parsing does not return to the
supervisor. The TLS server name comes from immutable bootstrap configuration,
not from the worker's dial request. The worker loads the platform trust store
during trusted startup, before confinement and before receiving untrusted
bytes, then closes any path handles used for that initialization.

The worker has no `socket`, `connect`, `bind`, `listen`, or `accept` authority.
If passing a connected socket is not enforceable on a platform, use a bounded
byte relay owned by the supervisor rather than granting ambient network access.
Proxy support, if added, must pass a post-CONNECT tunnel; the worker must never
receive a general proxy socket on which it can select another destination.

### Credential broker

The worker requests a credential using only `serverID` and a session token.
The supervisor verifies that the server has that credential reference and
returns only its current value:

- custody returns an access token, never the refresh token;
- a secret source returns only the one secret named by that server; and
- missing, revoked, or failed refreshes fail closed.

Resolution happens when an upstream session starts, not in the bootstrap.
Revocation closes affected upstream sessions so an already copied value is not
silently retained for the rest of the sandbox lifetime. Credential replies
have strict size limits and must never be formatted into errors or diagnostics.

### Local-server spawn broker

The worker requests a local server using only its configured server ID. For the
initial implementation the only accepted ID is the built-in `fs` server. The
supervisor maps that ID to the already resolved, fixed command:

```text
gantry-guest mcp-serve filesystem --root <configured-root> --user <configured-user>
```

The worker cannot supply or modify argv, environment, cwd, UID/GID, root, or
share configuration. The supervisor applies the global guest-session limit,
starts the helper without user secrets, and transfers or relays only its stdin
and stdout. A timeout, malformed upstream frame, worker exit, or session close
kills the helper rather than returning it to a pool.

### Audit channel

Use bounded structured events, not free-form worker log lines. Enumerated event
types carry server and tool names with existing length and character limits.
The supervisor quotes untrusted names before rendering them and never accepts
arguments, results, headers, URLs with query strings, or credential values as
audit fields.

Worker stderr goes through a supervisor-owned bounded log pipe. The worker does
not open its own log file.

## Host worker confinement contract

The shared worker substrate now defines the fixed
`workerconf.ProfileMCP` and `MCPSpec`. Reusing `ProfileNetwork` would grant too
much: the MCP worker needs I/O on delegated connected streams, not ambient
socket creation. The profile remains a compile-time audited allowlist, not a
runtime-configurable syscall policy.

The desired contract is:

- `NoNetwork=true`: no new socket or connection; connected streams arrive as
  capabilities;
- `NoExec=true`;
- `NoNewPaths=true` after trust-store initialization;
- `NoProcX=true`;
- a dense, allowlisted initial descriptor table plus the authenticated dynamic
  descriptor channel;
- a worker-specific task and memory limit; and
- no host file allowances or writable files.

Startup order is load-bearing:

1. re-exec `_mcp-worker` with only bootstrap, descriptor, diagnostic, and
   lifecycle handles;
2. authenticate and consume the bounded bootstrap;
3. load the system TLS roots while no guest or remote input is reachable;
4. close all ambient descriptors and path handles;
5. apply platform confinement and resource limits;
6. run the common in-worker verifier;
7. return a nonce-bound ready acknowledgement with the report; and only then
8. let the supervisor transfer a guest session, credential, local upstream, or
   remote connection.

No credential is released before the verified ready acknowledgement.

### Linux

Use the existing user, mount, and PID namespace machinery with a private empty
root. Apply `no_new_privs`, capability removal, task limits, descriptor-table
closure, and an MCP seccomp profile.

The profile permits Go runtime operations, TLS computation, and read/write on
existing descriptors. It denies path opens after startup and omits socket
creation, connect, bind, listen, accept, process execution, mount, ptrace, and
cross-process signalling. Dynamic descriptors arrive only on the inherited
SCM_RIGHTS channel.

The verifier must prove at least filesystem read/write denial, ambient network
dial denial, exec denial, process isolation, task limits, syscall policy, and
the initial descriptor table. A brokered positive test separately proves that
a delegated connected stream still works under the filter.

### macOS

Use a deny-default Seatbelt profile with no file, process-exec, or ambient
network allowances. Field-test whether reads and writes on connected sockets
transferred after `sandbox_init` remain usable. If Seatbelt applies destination
policy to those descriptors, use a supervisor byte relay; do not add broad
`network-outbound` merely to make the worker boot.

The TLS trust store must be loaded before Seatbelt or supplied as immutable
bootstrap material. The verifier reports actual file, network, process, and
exec results rather than assuming the profile worked.

### Windows

Create a separate process in a kill-on-close, one-process Job Object from the
first milestone. The existing Job-only tier is a process boundary, not a
filesystem or network boundary, and must report those properties as
unenforced.

Strict mode requires a field-proven restricted-token/AppContainer or equivalent
profile that can run Go TLS and inherited stream handles while denying ambient
file and network access. Until then, `-process-isolation=required` with MCP
fails closed on Windows. `auto` may run the separate Job-contained worker only
when `isolation.json` clearly reports the weaker properties.

## In-guest filesystem helper hardening

The guest helper remains a distinct process and continues to use `os.Root` for
race-resistant relative path traversal. Do not describe `os.Root` alone as a
process jail.

Before considering the filesystem capability hardened:

1. Stop silently using `/` as its root. Make the built-in filesystem server
   require an explicit `-mcp-fs-root`, with a compatibility warning before the
   default changes. Remote-only MCP must be able to disable the built-in
   filesystem server.
2. Open reads nonblocking and require `f.Stat().Mode().IsRegular()` before
   consuming bytes. Reject FIFOs, sockets, devices, and proc-style special
   files. Require a directory for `list_directory`.
3. Keep the current size, frame, directory-entry, session, and concurrency
   bounds, but kill and recreate a helper after a call timeout; cancelling only
   the waiter leaves a FIFO-blocked helper unusable.
4. Validate that the configured root is an absolute guest path selected by
   trusted host configuration. Treat a root path controlled through an
   untrusted ancestor at helper startup as unsafe because `os.OpenRoot` follows
   symlinks while selecting the initial directory.
5. Add a Linux spike for Landlock or a private mount namespace rooted at the
   selected directory, followed by capability removal, `no_new_privs`, UID/GID
   drop, and a small seccomp profile. Ship this only when an in-helper verifier
   proves it on the supported guest kernel; otherwise report `os.Root` plus UID
   isolation honestly.

Even after those changes, a readable hard link or bind mount deliberately
placed beneath the selected root remains part of the delegated tree. The root
must therefore be a narrow workspace without nested proc/device mounts.

## Lifecycle and failure semantics

- Start the MCP worker only when MCP is enabled; use one worker per sandbox.
- Do not retain an in-supervisor fallback gateway. In `auto`, the worker process
  is still mandatory but platform confinement may report degradation. In
  `required`, every mandatory MCP property must be verified or sandbox startup
  fails. In `off`, the role runs as an explicitly unconfined worker so the code
  path remains split and the report says disabled.
- If the worker cannot bootstrap, configured MCP startup fails loudly rather
  than silently starting without the requested capability.
- If the worker exits after VM readiness, close all MCP listeners and sessions,
  kill local helpers, revoke descriptor tokens, and audit the failure. The VM
  and ordinary `gantry exec` sessions remain available because MCP is not a VM
  enforcement point.
- The first implementation does not automatically restart a failed worker.
  Restart can be added later with rate limits, a fresh nonce, fresh credentials,
  and no reuse of old descriptors or sessions.
- Supervisor shutdown closes the worker Job/containment handle and escalates to
  termination if graceful drain exceeds a short deadline.

## Effective-state reporting

Bump `isolation.json` when the worker lands and add an `mcpConfinement` report.
When MCP is enabled, filesystem and process boundary summaries include the MCP
worker's verified properties. The report must distinguish:

- process split established;
- OS confinement applied;
- ambient network denied;
- origin dialing brokered;
- local execution brokered; and
- credential release scoped by server ID.

The first three are in-worker probe results. The final three are topology and
protocol properties established by supervisor tests; they must not be inferred
from a successful process spawn. The TUI should display degraded MCP isolation
without implying that the VMM or network worker also degraded.

## Package shape

Follow the existing trusted-half/untrusted-half convention:

```text
internal/sandbox/mcpworker/   trusted supervisor handle, spawn, brokers
internal/mcpworker/           worker runtime and bootstrap protocol
internal/sandbox/mcpgw/       MCP engine during extraction; move only if it
                              makes the dependency direction clearer
internal/sandbox/worker/      shared launch, channels, lifecycle, containment
internal/workerconf/          ProfileMCP, platform policy, verifier support
cmd/gantry                    hidden _mcp-worker role dispatch
```

Do not fork the MCP engine into in-process and worker copies. Tests may run the
engine in process behind interfaces, but production has one worker-owned path.

## Implementation milestones

### Foundation — generic worker launch (complete)

- typed VMM, network, and MCP roles;
- empty-by-default role environments and exact platform capability tables;
- shared re-exec, bounded diagnostics, namespace/Job setup, lifecycle,
  termination, reaping, containment cleanup, and nonce-bound channels; and
- VMM and network worker migration without moving their role-specific policy,
  asset validation, or failure semantics into the harness.

### M0 — Guest filesystem hardening

- require or warn toward an explicit narrow filesystem root;
- reject non-regular read targets and non-directory list targets;
- kill timed-out local helpers; and
- add traversal, symlink-race, FIFO, device/proc, and timeout regressions.

This reduces current risk independently of the host split.

### M1 — Worker protocol and process split

- add the hidden role and consume the shared launch, bootstrap, lifecycle,
  diagnostics, and dynamic descriptor-transfer primitives;
- move guest MCP parsing, session muxing, policy, local stdio parsing, and
  remote protocol handling into the worker; and
- remove the production in-supervisor gateway path.

M1 is an implementation checkpoint, not a security release by itself.

### M2 — Capability brokers

- add server-ID-only dial, credential, and local-spawn requests;
- enforce immutable supervisor mappings and global limits;
- pass connected streams instead of ambient network authority; and
- ensure the worker receives no refresh token, share root, arbitrary argv, or
  unrelated secret.

M1 and M2 must land together in a release.

### M3 — Linux confinement and reporting

- activate `ProfileMCP` with a private root, task limits, and verifier probes;
- extend `isolation.json`, the TUI, and `-process-isolation=required`; and
- field-run the Linux KVM confinement battery with active local and remote MCP
  sessions.

### M4 — macOS and Windows enforcement

- field-test post-confinement connected-stream transfer under Seatbelt;
- implement a relay fallback if descriptor use requires ambient network rules;
- keep Windows Job-only results honest while developing a strict token or
  AppContainer tier; and
- refuse `required` wherever mandatory properties cannot be proved.

### M5 — Optional credential/policy strengthening

If MCP credentials need to survive arbitrary worker compromise, introduce a
second minimal transport broker that injects and redacts credentials without
releasing them to the MCP worker. This requires a carefully bounded request
protocol and duplicates part of HTTP enforcement; it should be justified by a
stronger threat model rather than folded casually into the initial split.

## Test and acceptance plan

### Unit and fuzz tests

- bootstrap version, nonce, size, duplicate-ID, and unknown-field rejection;
- one-use descriptor tokens, wrong-channel tokens, replay, expiry, and cleanup;
- broker requests cannot supply an address, URL, argv, credential name, or
  sandbox ID;
- destination validation and DNS pinning remain race-free;
- credential resolution is server-scoped, refresh-aware, revocable, and absent
  from every error and log;
- local spawn maps only the built-in ID to fixed argv;
- worker death closes all pending calls and helper processes;
- existing MCP frame, HTTP/SSE, redaction, policy, and concurrency fuzzing runs
  against the worker transport; and
- filesystem tests cover concurrent symlink replacement and blocking special
  files, not only static `..` examples.

### In-worker negative probes

From the real child process, prove that attempts to do all of these fail:

- read and create a regular file outside its private root;
- execute the Gantry binary or another program;
- dial public Internet, host loopback, LAN, metadata, or a Unix socket;
- enumerate or signal the supervisor;
- exceed the worker task limit; and
- discover an inherited descriptor not listed by the bootstrap contract.

Positive controls prove authenticated control traffic, a transferred guest
session, and a supervisor-dialed remote TLS stream still work.

### End-to-end batteries

Extend the maintained Linux KVM and Windows WHPX batteries to assert:

- local read/list behavior and symlink escape refusal are unchanged;
- a remote mock sees the scoped credential while guest output, diagnostics,
  and audit remain value-free;
- custody refresh and secret revocation affect new sessions;
- unknown server IDs, redirects, metadata/private addresses, and credential
  cross-use fail closed;
- 16 sessions and in-flight limits remain enforced in both worker and
  supervisor;
- killing `_mcp-worker` fails MCP sessions without killing ordinary sandbox
  exec;
- killing the supervisor reaps the worker and guest helpers;
- `isolation.json` reports the measured MCP properties; and
- `required` fails on an intentionally unavailable control instead of silently
  falling back.

Acceptance requires `go test`, race tests, `go vet`, `golangci-lint`, all
cross-builds, and real KVM/WHPX replay. macOS confinement is not marked
implemented until the Seatbelt descriptor-transfer path boots and passes the
same negative probes on Apple silicon.
