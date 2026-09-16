# MCP confinement

This page summarizes the MCP security boundary. The canonical process and
capability flow is in [Architecture](architecture.md#mcp-worker); user setup is
in [MCP gateway](mcp-gateway.md).

## Status

Every MCP-enabled sandbox uses a separate `_mcp-worker`; production does not
parse MCP in the trusted supervisor. Linux and Windows confinement are
implemented and measured in `isolation.json`. macOS uses Seatbelt, but complete
Apple-silicon field validation remains follow-up work.

The in-guest filesystem server is a separate unprivileged process. Its
`os.Root` traversal checks provide path containment, not a complete process
sandbox.

## Boundary

```text
trusted supervisor                     confined MCP worker
------------------                     ---------------------
server map and lifecycle    streams     MCP / JSON / SSE parsing
secret and OAuth stores   <--------->   tool filtering and ID mapping
DNS-pinned origin dialing               TLS and response redaction
fixed guest-helper launch               no ambient path/net/exec access
```

The supervisor accepts guest MCP connections but relays opaque bounded bytes.
The worker can request only a configured server ID. It cannot provide a URL,
address, path, command, credential name, or sandbox ID.

The supervisor keeps:

- secret sources and OAuth refresh tokens;
- destination validation and DNS pinning;
- host shares, writable disks, and sandbox control state;
- fixed local-helper commands; and
- audit persistence and worker lifecycle.

The worker receives:

- an immutable list of configured server IDs and tool rules;
- bounded guest, local-server, and upstream streams; and
- one current credential for a configured upstream when needed.

No credential is released before the worker reports its verified confinement
state.

## Confinement

All platforms start the worker with an exact handle table, authenticated
nonce-bound channels, bounded streams, task limits, no child execution, and no
host file allowances.

- **Linux:** private namespaces and root, capability removal, `no_new_privs`,
  deny-all Landlock filesystem policy, and an MCP seccomp allowlist.
- **macOS:** deny-default Seatbelt with no file, process-exec, or ambient
  network access.
- **Windows:** zero-capability AppContainer in a one-process, kill-on-close Job,
  with active file, network, and execution denial probes.

`-process-isolation=required` fails when required properties cannot be proved.
`auto` may report degraded OS confinement. `off` still keeps MCP in a separate
process but disables the confinement claim.

## Residual risk

A compromised MCP worker can misuse credentials and connections already
delegated to an active configured server. It may call tools that its own tool
filter would normally deny, read or alter active MCP payloads, and disrupt MCP
service.

It must not gain arbitrary host files, processes, destinations, refresh tokens,
unrelated secrets, or another sandbox's channels. Preserving tool policy after
worker code execution would require a second trusted MCP-aware enforcement
layer and is not currently provided.

A configured remote server receives its credential and requested data by
design. Response redaction reduces accidental reflection but cannot stop a
malicious server from transforming or encoding a secret.

## Guest filesystem helper

The built-in filesystem server runs inside the microVM as a non-root guest user
and uses `os.Root` for race-resistant relative lookup. Use a narrow explicit
`-mcp-fs-root`, preferably over a read-only share. Files intentionally reachable
through hard links or nested mounts under that root are part of the delegated
tree.

Further hardening tracks rejection of special files, timeout recovery, and an
independently verified guest process sandbox. Until then, do not describe the
helper as a complete filesystem jail.

## Failure and evidence

If the MCP worker fails, Gantry closes MCP listeners, sessions, and local
helpers. The VM and normal `gantry exec` sessions remain available. Supervisor
shutdown reaps the worker.

`isolation.json` records whether the process split, OS confinement, ambient
network denial, brokered origin dialing, fixed local execution, and scoped
credential release were established. Tool decisions are useful audit events,
but they are not trustworthy after worker compromise.

Tests cover malformed bootstrap and stream frames, capability-scope failures,
credential isolation, destination validation, worker death, confinement probes,
and real local and remote MCP sessions. See [Security](security.md#worker-processes)
for the overall sandbox threat model.
