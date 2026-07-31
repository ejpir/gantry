# `pi attach` v1 — implementation plan (grounded in a read of pi 0.82.1)

Source inspected: npm package `@earendil-works/pi-coding-agent@0.82.1`
(`dist/` maps 1:1 onto the TS source). This plan supersedes the RFC's
assumptions where the code disagrees — mostly in our favor.

## Implementation status (2026-07-29, branch `pi-attach-v1` in `../pi`)

**P0 protocol — DONE.** Commits `3f1b990` + `935f748b`:
- `hello` greeting on every attach (protocol 1, version, sessionId, cwd,
  capabilities); tolerant non-JSON parsing before hello
- `shutdown` / `detach` commands with the RFC semantics
- `fs_complete` / `read_file` / `list_sessions` commands
  (`src/modes/rpc/fs-commands.ts`, Node-walk v1, no .gitignore)
- Socket serving: `pi --mode rpc --sock PATH` (deviation from the RFC's
  `pi agent --serve-sock` sugar — same function, fits the existing flag
  style; `--serve-*` aliases can be added later without new plumbing)
- Socket file `0600`; stale-socket reclaim, live-socket steal refusal

**P1 transport — DONE.** `RpcClient` supports three transports: legacy
`node cli.js` spawn, arbitrary shell `command` (ssh/docker exec/gantry exec
— this is `--cmd` attach's whole mechanism), and `socketPath`. Hello
verification with clear errors for non-RPC transports; protocol version
check; `shutdown/detach/fsComplete/readFile/listSessions/respondToExtensionUI/
getHello/hasCapability/onClose` methods; graceful `stop()` (shutdown command
before SIGTERM, detach for sockets).

**P3 lifecycle (server side) — DONE.** Takeover with `{type:"detached",
reason:"takeover"}` notice; explicit detach → immediate auto-resolve of
pending UI (headless semantics); connection loss → 30s grace window,
requests re-armed and re-emitted on reconnect (reuses the existing
per-request timeout machinery, as planned). Client-side reconnect UX
remains with P2.

**Tests — 28 new, all green; zero regressions** (1672 pass; the 15
failures in CLI-spawning tests are pre-existing environment issues —
`node src/cli.ts` requires native TS support absent in this sandbox's
node build; verified failing on the base commit).
- `test/rpc-fs-commands.test.ts` (11): completion semantics, pruning,
  scoping, limits; read_file errors/binary/truncation
- `test/rpc-lifecycle.test.ts` (11): hello, fs/session commands over
  mocked stdio; takeover/detach/grace/reconnect/grace-expiry/shutdown
  with fake connections
- `test/rpc-socket-client.test.ts` (7): real socket + RpcClient round
  trips, detach-and-reattach, takeover, shutdown, non-RPC socket
  rejection, ECONNRESET survival

**Live smoke — DONE.** Real provider (kimi-coding OAuth) over a real
socket: hello → get_state → fs_complete (agent-side cwd) → read_file →
prompt with streaming → shutdown. Caught and fixed a real bug: server
crashed on unhandled ECONNRESET when a client vanished mid-write
(`935f748b`).

**P2 TUI decoupling — IN PROGRESS.** Plan: `pi-attach-p2-plan.md`.
**P2.1 DONE** (commit `c1093a56`): 14 new protocol commands (get_resources,
get_context_usage, get_tools, set_scoped_models, navigate_tree, reload,
export_jsonl, clear_queue, abort_compaction, abort_branch_summary,
get_auth_status, refresh_models, rename_session, get_system_prompt),
`scopedModels` in get_state, `argumentHint` on get_commands, and the
`session_changed` server event — server + client + types + 9 tests, all
verified live against a real socket agent.

**P4 gantry — blocked on P2** (no client to point at the serve side yet).
Current `gantry pi` (pty streaming) remains the shipping path.

## 0. The headline: the protocol is already ~90% built

The RFC's §3.1 "gaps" are almost all **already closed** in
`dist/modes/rpc/`:

| RFC assumption | Reality in 0.82.1 |
|---|---|
| "Bidirectional UI must be added" | `extension_ui_request` covers **all nine** `ctx.ui` methods (select, confirm, input, editor, notify, setStatus, setWidget, setTitle, set_editor_text), with per-request `timeout` that **auto-resolves on expiry** (`rpc-mode.js:63`) — the detached-state semantics from RFC §3.1 already exist mechanically |
| "Session-control audit needed" | 40+ `RpcCommand` types: `prompt/steer/follow_up/abort`, `new_session`, `set_model/cycle_model/get_available_models`, thinking-level trio, steering/follow-up modes, `compact/set_auto_compaction`, retry trio, `bash/abort_bash`, `switch_session/fork/clone/get_tree/get_entries`, `export_html`, `set_session_name`, `get_commands`, `get_state` |
| "Interrupt must become a command" | `abort` + `abort_bash` + `abort_retry` already exist |
| "Client facade must be built" | `RpcClient` (`dist/modes/rpc/rpc-client.js`) is a typed client: spawns the agent, correlates request ids, `onEvent()`. Public via the package's `./rpc-entry` export |
| "No working TUI client exists" | `examples/rpc-extension-ui.ts` is a working custom TUI — including select/confirm/input/editor dialogs — proving the wire protocol supports a real UI end-to-end |

**What v1 actually is:** (a) small protocol additions, (b) transport
generalization of `RpcClient`, (c) the stock TUI as a client, (d) lifecycle
semantics. Only (c) is large.

## 1. Architecture map (as found)

```
cli.js ── mode ──┬─ interactive/InteractiveMode ─┐
                 ├─ print-mode                   ├─ all take AgentSessionRuntime
                 └─ rpc/runRpcMode ──────────────┘   ("runtimeHost")

AgentSession (core/agent-session.js): the facade.
  subscribe(listener) → AgentSessionEvent stream
  ~70 public methods; RPC mode is a thin serializer over them

InteractiveMode (5056 lines) touches session via ~40 members.
  Top coupling: modelRuntime×27, scopedModels×11, prompt×11,
  extensionRunner×11, resourceLoader×10 — then long tail of
  state getters + commands that all map to existing RPC.

RpcClient: spawn("node", [cliPath, ...args])   ← command hardcoded
```

## 2. Gap analysis (what's genuinely missing)

### 2.1 Protocol additions — all small
1. **`hello` handshake.** rpc-mode emits nothing on startup; `RpcClient.start()`
   resolves immediately. Add `{type:"hello", protocol:1, sessionId, capabilities[]}`
   as the first line; client verifies before accepting commands.
2. **Lifecycle commands.** No `shutdown`, no `detach`. `RpcClient.stop()` just
   kills the child. Add both to `RpcCommand` (+ responses).
3. **Filesystem commands** (the RFC's open question #1 — confirmed real):
   - `@file` completion shells out to **`fd`** (auto-downloaded by the CLI,
     `interactive-mode.js:465`) against the *local* fs → needs
     `fs_complete(prefix) → paths[]` executed agent-side.
   - File mentions / `@file` content injection → `read_file(path)`.
   - **Session picker**: `switch_session(path)` exists but *listing*
     `~/.pi/agent/sessions/*.jsonl` is local-fs today → `list_sessions()`.
   - Image paste: **no gap** — clipboard is client-local and `prompt` already
     takes `images: ImageContent[]` over the wire.
   - `$EDITOR` (external-editor.js): **no gap** — edits prompt text locally,
     result goes over as the prompt string. Stays client-side by design.
4. **`--serve-sock`.** rpc-mode reads stdin only; add a unix-socket listener
   variant that speaks the identical line protocol (plus peer-cred check
   `SO_PEERCRED`/equivalent, RFC OQ#4).

### 2.2 RpcClient transport generalization — small
- Un-hardcode `node`: `RpcClientOptions.command` (default preserves today's
  `node cli.js`). This one-line-class change makes
  `pi attach --cmd 'ssh …'` / `--cmd 'gantry exec … pi agent --serve-stdio'`
  work — the child stdio *is* the transport, runtimes bridge it.
- Socket client: `net.connect(path)` in place of child stdio; expose
  `transport: {type:"spawn"} | {type:"socket"}`.
- Verify `hello`; fail loudly on version mismatch (RFC OQ#5).

### 2.3 InteractiveMode decoupling — the bulk of v1
The TUI is well-factored ("delegating business logic to AgentSession") but
binds to the concrete class, including deep objects that can't cross a wire
(`modelRuntime`, `extensionRunner`, `resourceLoader`, `sessionManager`,
`settingsManager`, `agent`, `state`).

**Approach: introduce a `SessionDriver` interface** sized by the ~40 actual
touch points, with two implementations:

- `LocalSessionDriver` — wraps `AgentSessionRuntime` (today's behavior;
  mostly pass-through, zero perf risk to the default path).
- `RemoteSessionDriver` — backed by `RpcClient`; events from `onEvent`,
  commands from the typed API.

The touch-point inventory resolves as:

| TUI need | Resolution |
|---|---|
| prompt/steer/followUp/abort/compact/setModel/cycle*/set*bashes, navigateTree, export | existing RPC commands — direct map |
| isStreaming/isCompacting/model/thinkingLevel/scopedModels/sessionFile/sessionName/pending counts | `get_state` + keep local copy updated from events |
| `subscribe()` → rendering | `onEvent()` — same `AgentSessionEvent` type already crosses RPC |
| `modelRuntime` (×27 — model picker metadata) | extend `get_available_models` payload to carry the metadata the picker renders (pricing, context window, reasoning) — audit picker first |
| `extensionRunner`/`resourceLoader` (slash cmds, prompt templates, skills for autocomplete) | `get_commands` already returns extension/prompt/skill commands; check prompt-template args survive; add `reload` command if /reload must work remotely |
| `settingsManager` | **client-local by design** — theme, keybindings, editor prefs belong to the terminal side. Split: session-scoped settings (auto-compaction…) via RPC, UI-scoped settings local |
| `systemPrompt`, `tree`, `state`, `sessionManager` introspection | audit per-use; add `get_*` commands only where the UI genuinely renders it |
| ctx.ui dialogs from extensions | client answers `extension_ui_request`s — pattern already proven by `examples/rpc-extension-ui.ts` |

InteractiveMode itself changes only at construction (`driver:` instead of
`runtimeHost:`) plus deletion of code paths that move into the drivers.

**Effort:** the honest estimate. P0+P1: days. P2: 1–2 weeks against the
touch-point list, dominated by the modelRuntime/picker audit and the
settings split. P3: days.

### 2.4 Lifecycle semantics (RFC §3.2/3.3)
- `attach --cmd` → spawn, own, `shutdown` on TUI exit.
- `attach --sock` → `detach` on exit; **takeover** on second connect (server
  tracks one active client; new connection replaces it with a notice).
- **Grace window**: reuse the existing per-request timeout machinery — when
  the client drops *without* `detach`, the server re-arms pending/new
  `ui_request`s with a ~30s timeout instead of auto-resolving immediately;
  expiry → auto-resolve (RFC §3.1 transition rule). This is a small change to
  `createDialogPromise` in rpc-mode.js, not new machinery.
- Reconnect UX: socket case only for v1 (RFC §3.2 scope note stands).

## 3. Phases

```
P0 protocol        hello, shutdown/detach, fs_complete/read_file/list_sessions,
                   serve-sock + peer creds                       [rpc-types, rpc-mode]
P1 transport       RpcClient command override, socket transport,
                   hello verification                            [rpc-client]
P2 TUI decouple    SessionDriver iface + Local/Remote impls;
                   modelRuntime & settings audit; wire
                   extension_ui handling into attach             [interactive, core]
P3 lifecycle       takeover, grace window, reconnect UX          [rpc-mode, attach cmd]
P4 gantry          `gantry pi-agent --serve` (start-or-attach +
                   exec pi agent --serve-stdio), settings.json
                   spawn snippet, docs update                    [this repo, pi.go]
```

P0–P1 are independently mergeable (additive, no behavior change).
P2 lands behind `pi attach` being the only consumer of `RemoteSessionDriver`.
P4 waits on nothing but a pi release containing P0–P2.

## 4. Risks / decisions to confirm against source

1. **Model picker metadata** — the single most likely place the facade leaks.
   `get_available_models` returns `{provider,id,contextWindow,reasoning}`;
   if the picker renders more (pricing, aliases), extend the payload.
2. **Settings split** — deciding which settings are session-scoped vs
   UI-scoped needs a pass over `SettingsManager` consumers in the TUI.
3. **`/reload` and session picker UX** — both are local-fs-centric today;
   decide remote semantics (`reload` command; `list_sessions` + picker) or
   v1-document them as local-only in attach mode.
4. **Event volume** — the full `AgentSessionEvent` stream already crosses
   RPC in production (rpc mode + web UIs), so throughput is proven; the
   15s/5000-line pty relay we use in gantry is far heavier.
5. **The `timeout`-based grace window** must not surprise extensions that
   already pass their own `timeout` — document precedence (client-loss
   re-arm wins over, not stacks with, extension timeout).

## 5. What this means for the RFC before sending

Update the RFC with a "status against 0.82.1" appendix: §3.1 items 1–3 exist
(ui bridge, session control, abort); open question #2 (TUI coupling) is now
answered with the touch-point inventory; open question #1 narrowed to
`fd`-completion + session listing (image paste and $EDITOR verified
non-issues). It turns the proposal from "please build a protocol" into
"please let the stock TUI speak the protocol you already ship" — a much
smaller ask.
