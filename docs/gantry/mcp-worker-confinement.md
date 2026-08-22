# MCP Worker and Filesystem Confinement Design

**Status:** the host `_mcp-worker`, capability relays, scoped credential and
spawn brokers, Linux Landlock/seccomp profile, Seatbelt profile, Windows Job
boundary, and effective-state reporting are implemented. The in-guest
filesystem helper remains a separate unprivileged process, but its `os.Root`
is path containment rather than a complete process sandbox. Apple-silicon
field validation and a strict Windows filesystem/network boundary also remain.

This design separates those two concerns:

1. keep the host MCP protocol and remote-HTTP attack surface in a confined
   `_mcp-worker`; and
2. harden the existing in-guest filesystem helper without moving host paths or
   share roots into a host worker.

The worker architecture follows the existing
[VMM and network worker model](architecture.md#host-components): one
executable, a role-specific capability set, authenticated bootstrap channels,
platform [worker confinement](security.md#worker-processes), and in-worker
verification reported through `isolation.json`.

## Decision

`mcpgw` runs outside the trusted supervisor in one worker per MCP-enabled
sandbox. Keep the secret store, OAuth refresh tokens, destination
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
so the loss is scoped but real. Supervisor-issued capabilities limit this
broker authority to the lifetime of an accepted guest session; they do not
prevent a compromised worker from misusing configured upstream authority while
such a session is active.

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
                                                 | supervisor-connected stream
                                                 | over bounded opaque relay
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

The supervisor accepts the local MCP connection but does not parse MCP bytes.
It copies bounded opaque chunks over the worker's authenticated stream
multiplexer. The same relay carries supervisor-connected remote streams and
fixed guest-helper stdio, avoiding `accept`, socket-creation, and dynamic
handle-transfer authority in the worker on every host platform.

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

Use separate authenticated channels for control, reverse broker requests, and
the bounded stream multiplexer. Data from the guest never shares framing with
trusted capability commands. Every request, reply, and stream frame is
length-bounded, deadline-aware, and concurrency-limited in the supervisor. An
unknown method, malformed frame, nonce failure, stream-ID parity error, or
unknown stream is a fatal worker protocol violation.

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

### Guest-session streams

The supervisor accepts the per-sandbox Unix socket or Windows endpoint,
applies a global session limit, and opens a supervisor-owned even-numbered
stream on the authenticated multiplexer. The worker applies its independent
session limit before parsing bytes. Worker-opened upstream streams use odd
IDs, so collisions and wrong-direction opens fail closed.

The supervisor copies opaque chunks but never decodes MCP payload bytes.
Closing either side or killing the worker reliably closes all active streams.

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
6. relays only that connected stream over the fixed multiplexer.

TLS remains in the worker so remote protocol parsing does not return to the
supervisor. The TLS server name comes from immutable bootstrap configuration,
not from the worker's dial request. The worker loads the platform trust store
during trusted startup, before confinement and before receiving untrusted
bytes, then closes any path handles used for that initialization.

The worker has no `socket`, `connect`, `bind`, `listen`, or `accept` authority.
The implementation always uses the bounded supervisor relay rather than
platform-specific dynamic descriptor transfer. Proxy support, if added, must
pass a post-CONNECT tunnel; the worker must never
receive a general proxy socket on which it can select another destination.

### Credential broker

The worker requests a credential using only `serverID` and an opaque session
capability issued by the supervisor when it accepts the guest connection. The
supervisor tracks live capabilities and rejects fabricated, expired, or revoked
values before looking up the server. It then verifies that the server has that
credential reference and returns only its current value:

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
and stdout through the bounded relay. A timeout, malformed upstream frame,
worker exit, or session close kills the helper rather than returning it to a
pool.

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

The enforced contract is:

- `NoNetwork=true`: no new socket or connection; connected streams arrive as
  capabilities;
- `NoExec=true`;
- `NoNewPaths=true` after trust-store initialization;
- `NoProcX=true`;
- a dense, allowlisted initial descriptor table plus fixed authenticated
  control, reverse-broker, and stream-relay channels;
- worker-specific task limits plus bounded frames, streams, sessions, and
  in-flight calls; and
- no host file allowances or writable files.

Startup order is load-bearing:

1. re-exec `_mcp-worker` with only bootstrap, broker, stream-relay,
   diagnostic, and lifecycle handles;
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

The existing user, mount, and PID namespace machinery creates a private empty
root. Gantry applies `no_new_privs`, capability removal, task limits,
descriptor-table closure, a deny-all Landlock filesystem ruleset, and the MCP
seccomp profile.

The profile permits Go runtime operations, TLS computation, and read/write on
existing inherited relay descriptors. It denies path opens after startup and
omits socket creation, connect, bind, listen, accept, SCM_RIGHTS, process
execution, mount, ptrace, and cross-process signalling.

The verifier proves filesystem read/write denial, ambient network dial denial,
exec denial, process isolation, task limits, Landlock and syscall policy, and
the initial descriptor table. A brokered positive test separately proves that
a relayed connected stream still works under the filter.

### macOS

macOS uses a deny-default Seatbelt profile with no file, process-exec, or
ambient network allowances. Its fixed inherited pipe relay needs no
`network-outbound` rule. Apple-silicon field validation must still verify the
complete post-`sandbox_init` MCP path before strict support is claimed.

The TLS trust store must be loaded before Seatbelt or supplied as immutable
bootstrap material. The verifier reports actual file, network, process, and
exec results rather than assuming the profile worked.

### Windows

Windows creates a separate process in a kill-on-close, one-process Job Object.
The Job-only tier is a process boundary, not a filesystem or network boundary,
and reports those properties as unenforced.

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
  kill local helpers, revoke stream capabilities, and audit the failure. The VM
  and ordinary `gantry exec` sessions remain available because MCP is not a VM
  enforcement point.
- The first implementation does not automatically restart a failed worker.
  Restart can be added later with rate limits, a fresh nonce, fresh credentials,
  and no reuse of old descriptors or sessions.
- Supervisor shutdown closes the worker Job/containment handle and escalates to
  termination if graceful drain exceeds a short deadline.

## Effective-state reporting

`isolation.json` version 3 includes `mcpConfinement` and `mcpBoundary`.
When MCP is enabled, filesystem, network, and process boundary summaries include
the MCP worker's verified properties. The report distinguishes:

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

### M1 — Worker protocol and process split (complete)

- add the hidden role and consume the shared launch, bootstrap, lifecycle,
  diagnostics, and bounded stream-relay primitives;
- move guest MCP parsing, session muxing, policy, local stdio parsing, and
  remote protocol handling into the worker; and
- remove the production in-supervisor gateway path.

M1 is an implementation checkpoint, not a security release by itself.

### M2 — Capability brokers (complete)

- add server-ID-only dial, credential, and local-spawn requests;
- enforce immutable supervisor mappings and global limits;
- relay connected streams instead of granting ambient network authority; and
- ensure the worker receives no refresh token, share root, arbitrary argv, or
  unrelated secret.

M1 and M2 must land together in a release.

### M3 — Linux confinement and reporting (host path complete)

- `ProfileMCP` uses a private root, Landlock, task limits, and verifier probes;
- `isolation.json` and `-process-isolation=required` include MCP; and
- the Linux KVM confinement battery exercises active local and remote MCP
  sessions.

The TUI now manages configured MCP servers and restart-required state. A
worker-confinement evidence view remains follow-up work; the version 3
`isolation.json` file is currently the authoritative detailed view.

### M4 — macOS and Windows enforcement (partial)

- field-test the complete inherited-relay path under Seatbelt on Apple silicon;
- use the cross-platform relay without adding ambient network rules;
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
- stream-ID parity, unknown/duplicate IDs, close races, queue saturation, and
  cleanup;
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
