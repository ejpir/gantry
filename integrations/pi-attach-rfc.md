# RFC: Decouple the TUI from the agent process — `pi agent --serve` / `pi attach`

**Status:** draft, for discussion — **updated after a code read of pi 0.82.1**
(see the appendix: most of the protocol this RFC originally proposed *already
exists and ships* in `--mode rpc`)
**Audience:** pi maintainers
**TL;DR:** Let the stock TUI attach to an agent running in another process —
locally, in a container, in a VM, or over SSH — by speaking the RPC protocol
pi already ships over a stream transport. This is the LSP/DAP pattern, and
Codex already ships it (`codex app-server` powers their VS Code extension).

## 1. Summary

Today the TUI drives `AgentSession` in-process: it calls methods and
subscribes to events directly. Pi also ships `--mode rpc`: a headless mode
speaking line-delimited JSON over stdio, whose protocol is — verified against
0.82.1 — **remarkably complete**: 40+ command types covering prompting,
interrupt, model/thinking control, compaction, session tree operations, and a
full bidirectional extension-UI bridge with per-request timeouts. What does
not exist is any way for the *stock TUI* to be a client of that protocol.
Anyone who wants the agent in a different process (or machine, or sandbox)
must either stream a raw pty or reimplement a UI from scratch.

This RFC proposes two additions:

```
pi agent --serve-stdio            # rpc mode + handshake/lifecycle/fs additions
pi agent --serve-sock PATH        # same, on a unix socket

pi attach --cmd 'ssh devbox pi agent --serve-stdio'
pi attach --cmd 'gantry exec proj -- pi agent --serve-stdio'
pi attach --sock ~/.pi/agent.sock
```

`attach` makes the stock TUI a *client* of the RPC protocol. Everything the
TUI renders — streaming messages, tool calls, extension dialogs — arrives as
events; everything the user does leaves as commands. Where the agent process
runs becomes a property of the transport, not of pi.

The ask is deliberately modest: **the protocol exists and is proven in
production** (RPC mode, the `RpcClient` public API, the web-ui and
`rpc-extension-ui` examples). What remains is a handful of additive commands,
a socket transport, and the TUI decoupling described in §3.2.

## 2. Motivation

### 2.1 Sandboxed and remote agents are a class, not a niche

Users increasingly want the agent process — which holds API credentials,
executes extensions, and processes untrusted prompt content — somewhere other
than the host holding the terminal:

- **VMs / microVMs** (gantry, Gondolin, firecracker setups): the whole agent
  loop inside a kernel boundary, TUI on the host.
- **Containers**: docker/devcontainer workflows where the toolchain lives in
  the image.
- **Remote dev boxes**: agent next to the code, developer on a laptop.
- **Managed sandboxes**: ephemeral, network-restricted environments for
  untrusted repositories.

Prompt injection is the sharp version of this argument: injected content
steers everything the agent *process* can do — credentials in its memory,
extension code execution, MCP server spawns — not just its tool calls.
Sandboxing only the tools leaves the confused deputy on the host holding keys.
Notably, when OpenAI needed real isolation for Codex, the cloud product runs
the *entire agent* inside the isolated environment; per-command sandboxing is
their local convenience model, not their isolation model.

### 2.2 Today's workarounds are all bad (including ours)

- **Stream a pty** (e.g. run pi inside a VM, relay the terminal): works — it
  is what our own runtime does today — but attacker-influenced bytes reach the
  user's terminal raw, and escape-sequence injection (OSC 52 clipboard writes,
  emulator CVEs) becomes part of the attack surface. The obvious fix — filter
  escapes in the relay — does not work: the relay sees the bytes but cannot
  distinguish the TUI's legitimate control sequences from injected ones in the
  same stream, so filtering either breaks the TUI or passes the attack.
- **Reimplement a UI on RPC mode**: the `rpc-extension-ui` example proves
  it's possible, but every sandbox runtime shouldn't need its own from-scratch
  UI when a polished stock TUI already exists.
- **Accept in-process**: the agent, its credentials, and its extensions stay
  on the host, and "sandboxing" degrades to per-tool mediation with a
  default-allow posture.

### 2.3 Precedents

- **LSP / DAP**: editor ↔ language/debug server over stdio JSON-RPC. The
  entire editor ecosystem standardized on "UI is a client of a process that
  lives elsewhere."
- **Codex**: `codex app-server` speaks JSON-RPC over stdio; their VS Code
  extension is a thin client of it. The stock-TUI-attach proposal is exactly
  this, for pi's own TUI.
- **tmux / emacsclient**: detach/reattach semantics for long-lived sessions
  users don't want to lose.

## 3. Proposal

### 3.1 Serve side: small additions to an already-complete protocol

`pi agent --serve-stdio` is today's RPC mode plus the following. What already
exists (and needs no change): the full command surface (`prompt/steer/
follow_up/abort`, `new_session`, model and thinking-level control, compaction,
bash, `switch_session/fork/clone/get_tree/get_entries`, export, state,
commands), the event stream, and the extension-UI bridge —
`extension_ui_request` covers all nine `ctx.ui` methods, with per-request
`timeout` that auto-resolves on expiry.

The additions:

1. **`hello` handshake.** Today rpc-mode emits nothing at startup and clients
   just start sending commands. Add a first-line
   `{type:"hello", protocol:1, sessionId, capabilities:[...]}`; clients fail
   loudly on version skew. The parser must tolerate — and fail cleanly on —
   non-protocol bytes before `hello`: transport shims (ssh banners, host-key
   confirmations, MOTDs) write junk to the stream.

2. **Lifecycle commands: `shutdown` and `detach`.** Today the only way to end
   an RPC agent is to kill the process. Request ids remain scoped to a
   connection; outstanding requests are cancelled when the connection drops
   (a reattached client never sees stale ids).

3. **Detached is a defined state — and so is the transition into it.** With
   `--serve-sock`, an extension dialog may fire while *no* client is
   attached. Rule: detached behaves exactly like today's headless RPC mode —
   `ui_request`s auto-resolve (the existing timeout machinery) rather than
   queue, so an unattended agent never stalls on a dialog. Extensions that
   depend on interactive answers degrade without a client, exactly as they do
   for headless RPC users today.

   One transition needs care: *losing* a client is not the same as being
   *detached from* one. Without the distinction, a network blip would cancel
   a pending `confirm()` and re-fire it into the detached state —
   auto-answering, possibly destructively, a question the user never saw.
   So: an explicit `detach` command switches to auto-resolve immediately (the
   user chose to walk away); a dropped connection starts a short grace
   window (tens of seconds) during which `ui_request`s are held for a
   reconnecting client, falling back to auto-resolve only when it expires.
   Mechanically this is a re-arm of the existing per-request timeout on
   client loss, not new machinery. Cheap to specify now, awkward to retrofit.

4. **Filesystem commands** (verified gap — details in §3.2):
   `fs_complete(prefix)` for `@file` path completion, `read_file(path)` for
   file mentions, and `list_sessions()` for the session picker.

5. **`--serve-sock` transport.** The identical line protocol on a unix
   socket, with peer-credential checks so another local user can't attach to
   your agent (and its credentials).

### 3.2 Client side: the TUI gains a transport facade

`pi attach` swaps the TUI's in-process `AgentSession` handle for a driver
that serializes commands and re-emits events from the stream. A code read of
0.82.1 (details in the appendix) shows the TUI is well-factored for this —
it "delegates business logic to AgentSession" through ~40 member touches, and
the large majority map directly onto existing RPC commands and state. The
proposal: introduce a `SessionDriver` interface sized by that inventory, with
a `LocalSessionDriver` (today's behavior, pass-through) and a
`RemoteSessionDriver` (RpcClient-backed). InteractiveMode changes at
construction, not throughout.

Transports for v1:

| Transport | Flag | Covers |
|---|---|---|
| child process stdio | `--cmd '...'` | ssh, docker exec, gantry exec, any runtime that bridges stdio |
| unix socket | `--sock PATH` | local long-lived agents, detach/reattach |

(`RpcClient` today hardcodes `spawn("node", [cliPath, …])` — generalizing the
spawn command is a one-line-class change that makes every stdio-bridging
runtime work. The socket client is `net.connect` in place of child stdio.)

Explicitly **not** in v1: TCP (auth problems worth solving separately), vsock
(already covered by stdio-bridging runtimes; Node has no native AF_VSOCK
anyway), multiple concurrent clients, session recording/replay.

Three transport realities the v1 design must acknowledge:

- **Interactive transport startup.** `ssh devbox …` may prompt for a
  password, 2FA, or host-key confirmation on the same stdio the protocol is
  about to claim — every LSP-over-ssh implementation hits this. The child's
  **stderr is passed through** to the user's terminal; stdout stays protocol
  only. Document that transports must be non-interactive on stdout (ssh keys
  or ControlMaster, `BatchMode` recommended); combined with the tolerant
  pre-`hello` parser above, failure modes become clear errors instead of
  protocol corruption.
- **Second attach to a socket.** Multi-client is out of scope, but `--sock`
  needs a defined behavior when a client is already attached: **takeover** —
  the new client attaches, the old one is disconnected with a clear message.
  This is what tmux users expect (`reattach` implies the other terminal may
  still be connected), and it keeps v1 single-client without a "session
  locked" dead end. True multi-client can come later.
- **Reconnect scope.** v1 offers reconnect for the socket case (agent
  outlives the client by design). The `--cmd` case where the transport dies
  but the remote agent survives — an ssh drop — is where users would *most*
  want reconnect; it requires the remote end to outlive its stdio (double-fork
  + well-known socket), which is the runtime's concern. Named here as future
  work so it doesn't look overlooked.

**Host-side filesystem features, scoped by the code read.** The TUI is not a
pure renderer, but the verified gap is smaller than feared:

- `@file` path completion shells out to **`fd`** against the local fs
  (pi auto-downloads `fd` for exactly this) → genuinely needs the agent-side
  `fs_complete` command.
- `@file` content injection (file mentions) → needs agent-side `read_file`.
- The session picker lists `~/.pi/agent/sessions/*.jsonl` locally
  (`switch_session` already exists remotely) → needs `list_sessions`.
- **Image paste: no gap.** The clipboard is client-local and `prompt`
  already accepts `images: ImageContent[]` over the wire.
- **`$EDITOR`: no gap.** It edits prompt text locally and the result crosses
  as the prompt string; it should stay client-side by design.

### 3.3 Lifecycle semantics

- `attach --cmd`: pi spawns and **owns** the child. TUI exit → `shutdown`
  command → SIGTERM fallback.
- `attach --sock`: the agent is **shared**. TUI exit → `detach`; the agent
  keeps its context. This unlocks tmux semantics for agent sessions: detach
  at the office, reattach from home (takeover, per above), same context, same
  sandbox.
- If the transport dies mid-session, the TUI offers reconnect (socket case)
  rather than losing the session.

## 4. Security properties

- The host↔sandbox boundary becomes a **structured JSON stream** instead of a
  raw pty. To be precise about what this buys: the stock TUI renders
  attacker-influenced text in the local case too, so sanitization remains the
  TUI's job either way — but a structured stream makes sanitization
  *possible and centralized* (one renderer, typed fields, known display
  contexts), whereas a raw pty makes it impossible: the relay sees the
  bytes, but the TUI's legitimate control sequences and attacker-injected
  ones are indistinguishable in the same stream — filtering either breaks the
  TUI or passes the attack. Ship note: the sanitization audit of TUI
  rendering is follow-up work that matters with or without this RFC; attach
  is what makes it sufficient.
- The agent process — credentials, extensions, MCP servers, session state —
  can live entirely inside a sandbox; the host holds only a renderer and a
  codec. Host access becomes default-deny: the only things that cross are
  events and commands.
- Composes with runtime-level controls (network policy, credential injection
  at the sandbox boundary) for defense in depth.

Pi itself stays runtime-agnostic: it knows stdio and unix sockets. Sandbox
runtimes compete on "can you bridge stdio" — which every one of them can.

## 5. What this enables

```bash
# agent in a gantry microVM, stock TUI on the host
pi attach --cmd 'gantry exec myproject -- pi agent --serve-stdio'

# agent in a devcontainer
pi attach --cmd 'docker exec -i work pi agent --serve-stdio'

# agent on a remote box next to a huge repo
pi attach --cmd 'ssh -o BatchMode=yes devbox pi agent --serve-stdio'

# long-lived local agent, tmux-style
pi agent --serve-sock ~/.pi/agent.sock &
pi attach --sock ~/.pi/agent.sock        # detach, reattach later
```

And beyond this RFC: IDE and web frontends built on the *stock* protocol
instead of bespoke reimplementations, and per-project sandbox policy declared
in repo settings (`{"agent": {"spawn": "..."}}`) so `cd proj && pi` just does
the right thing.

## 6. Backwards compatibility

Fully additive. In-process TUI remains the default; `--mode rpc` behavior is
unchanged (new command types are inert to existing clients, `hello` is one
extra line at startup that well-behaved clients tolerate); no changes to
session files, settings, or the extension API beyond the new transport
plumbing.

## 7. Open questions

1. **Model picker metadata.** The TUI's heaviest session touch point is the
   model picker (~27 uses of `modelRuntime`). `get_available_models` returns
   `{provider, id, contextWindow, reasoning}`; if the picker renders more
   (pricing, aliases), the payload needs extending. This is the likeliest
   place the facade leaks.
2. **Settings split.** Which settings are session-scoped (travel with the
   agent: auto-compaction, steering modes) vs UI-scoped (stay with the
   terminal: theme, keybindings)? Needs a pass over the TUI's
   `SettingsManager` consumers; the RPC commands for session-scoped settings
   already exist.
3. **`/reload` and session picker semantics.** Both are local-fs-centric
   today. Remote equivalents (`reload` command, `list_sessions` + picker) —
   or v1 documents them as unavailable in attach mode.
4. **Socket auth.** Peer-credential checks on the unix socket (SO_PEERCRED or
   platform equivalent).
5. **UI latency.** Extension dialogs round-trip the transport — milliseconds
   on stdio/socket, irrelevant next to LLM latency, but worth a loading state.

## 8. Non-goals (v1)

- Multi-client attach / collaborative sessions (single client, with takeover)
- TCP or TLS transports
- Binary/attachment payloads over the protocol beyond what `prompt.images`
  already carries (bulk binary deserves a real design — chunked frames or a
  side channel — not an accident of v1)
- Session recording, replay, or migration between processes
- Sandbox lifecycle management (starting VMs/containers) — that's the
  runtime's job, via `--cmd`

## Appendix: verification against pi 0.82.1

Claims in this RFC were checked against the published npm package
(`@earendil-works/pi-coding-agent@0.82.1`; `dist/` maps 1:1 onto source):

| Proposal element | Status in 0.82.1 |
|---|---|
| Session-control commands (incl. `abort`, fork, compaction, model control) | **Ships** — 40+ `RpcCommand` types in `modes/rpc/rpc-types` |
| Extension UI bridge | **Ships** — `extension_ui_request` covers all nine `ctx.ui` methods; per-request `timeout` auto-resolves (`rpc-mode.js`) |
| Typed client | **Ships** — `RpcClient`, public via the `./rpc-entry` package export |
| Working TUI-on-protocol proof | **Ships** — `examples/rpc-extension-ui.ts` renders dialogs (select/confirm/input/editor) over the wire |
| `hello` handshake | **Missing** — rpc-mode emits nothing at startup |
| `shutdown` / `detach` lifecycle | **Missing** — `RpcClient.stop()` kills the child |
| Arbitrary spawn command | **Missing** — `RpcClient` hardcodes `spawn("node", [cliPath, …])` |
| Unix socket transport | **Missing** |
| `fs_complete` / `read_file` / `list_sessions` | **Missing** — `@` completion uses locally-spawned `fd`; picker lists the local sessions dir |
| TUI↔session decoupling | **Missing** — `InteractiveMode` (~5000 lines) binds the concrete `AgentSession`; ~40 member touches, most mapping to existing RPC; `modelRuntime` (model picker) is the deep coupling |

---

*Motivating implementation: gantry <!-- TODO: repo URL once public -->, a
microVM sandbox runtime, currently streams a pty out of the VM to give users
the stock pi TUI — it works, and it demonstrates both the demand for this
workflow and exactly why the pty approach should be replaced by a structured
transport. Its credential-sharing and network-policy design (agent
credentials mounted into the VM today, boundary-injected credentials as the
goal) is the "composes with runtime-level controls" point in §4.*
