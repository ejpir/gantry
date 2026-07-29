# P2 — TUI decoupling implementation plan (`pi attach`)

Companion to `pi-attach-v1-plan.md` (P0/P1/P3 status: DONE, branch
`pi-attach-v1` in `../pi`, commits `3f1b990`+`935f748b`). This plan is
grounded in a full touch-point inventory of `InteractiveMode` (5,056 lines)
and its components against pi 0.82.1 source.

## Status

**P2 COMPLETE** (`../pi` branch `pi-attach-v1`). Commits:

- `c1093a56` — P2.1 protocol surface (14 commands, `scopedModels`,
  `argumentHint`, `session_changed` event)
- `5e6c98b8` — P2.2/P2.3 facades (`RemoteAgentSession` +
  `RemoteAgentSessionRuntime`), `bashWithId`, 8 E2E tests
- `65fa24f1` — P2.4 `sessionPicker` seam (only TUI change besides one
  export seam; default behavior byte-identical)
- `2e25ab0c` — P2.5 `pi attach --cmd/--sock` entry point + arg parsing
- `a4b42431` — P2.6 facade completion from live pty smoke; `ModelInfo`
  barrel re-export fix
- `8f0a5c9f` — P2.7 docs (`docs/rpc.md` attach section) + `/export`
  async-variant seam

**Live verification (pty-driven, real LLM)**: stock TUI booted over
`--sock`, prompt submitted, reply streamed, session persisted
agent-side, footer rendered from the remote mirror (remote cwd, model,
context %), clean detach with server surviving, reattach rendered prior
history. 69 tests green across rpc/attach/interactive suites; every
commit passes the repo's pre-commit gate (biome, tsgo, shrinkwrap,
browser-smoke). Branch audited additive-only: all existing public
signatures byte-identical to base.

Remaining for real-terminal iteration (blind pty driving can't cover):
/resume picker navigation, /model selector, /tree + /fork, extension
dialog flows, escape/Ctrl+C edge cases.

## Strategy: remote facade, not TUI rewrite

`InteractiveMode` takes `runtimeHost: AgentSessionRuntime` **structurally**.
The TUI's entire session access flows through that one object and
`runtimeHost.session`. So instead of rewriting the TUI against a new
interface, we build:

- **`RemoteAgentSession`** — a facade implementing the exact
  `AgentSession` surface the TUI touches (~60 members), delegating to
  `RpcClient`, keeping a **live mirror** of session state fed by the event
  stream.
- **`RemoteAgentSessionRuntime`** — a facade for the runtime host surface
  (~10 members), including the extension-UI bridge that lets remote
  extensions render dialogs with the **stock TUI components**.

`InteractiveMode` ships unchanged except (a) construction site and (b) one
small seam for the session picker (see "Static seams" below). Zero risk to
the default local path; the entire attach experiment is additive code.

## Inventory findings that shape the design

1. **`this.settingsManager` is `session.settingsManager`** (a getter). The
   facade provides a real **local** `SettingsManager` — theme, keybindings,
   editor prefs are client-scoped (plan's settings split). Session-scoped
   settings (auto-compaction…) already have RPC commands.
2. **Template/skill expansion is agent-side**: `session.prompt()` expands
   `/template` and `skill:` invocations (`expandPromptTemplates` default
   true). The TUI only reads `name/description/argumentHint/filePath/
   sourceInfo` for autocomplete and the startup list → a `get_resources`
   command covers it; expansion comes free.
3. **`buildContextEntries(entries, leafId, byId)` is a pure exported
   function** → the sessionManager sub-facade computes it client-side over
   mirrored entries.
4. **The full `AgentSessionEvent` + `AgentEvent` stream already crosses
   the wire** (`entry_appended`, `message_end`, `queue_update`,
   `session_info_changed`, `thinking_level_changed`,
   `bash_execution_update`…) → the mirror can track nearly everything;
   prefetch fills the gaps.
5. **No `model_changed` event exists** — footer refresh is driven by the
   TUI's own post-command UI updates → mirror updates synchronously from
   each command's response.
6. **`session.bindExtensions({uiContext, mode:"tui"})` receives a real
   TUI-backed `ExtensionUIContext`** built from stock dialog components
   (selector, input, editor…). The facade stores it; incoming
   `extension_ui_request` events are dispatched to the matching uiContext
   method and the result returned as `extension_ui_response`. Remote
   extension dialogs render pixel-identically to local ones.
   `getEditorText`/`pasteToEditor` stay client-local (they operate on the
   TUI's own editor — same as today).
7. **Bash live output**: the TUI calls `session.executeBash(cmd, onChunk)`.
   The RPC `bash` command already routes through the server's
   `extensionRunner.emitUserBash` then `executeBash`, and streams
   `bash_execution_update` events carrying the originating command `id` —
   the facade wires `onChunk` to those events.
8. **OAuth flows are not remotable in v1**: `modelRuntime.login/logout`
   drive an interactive browser+localhost dance. Facade rejects with a
   friendly "authenticate on the agent host" status — documented
   degradation. `isUsingOAuth(provider)` is called synchronously per
   render → prefetch `get_auth_status` and cache.
9. **Session selector uses the *static* `SessionManager.list/listAll`**
   and `SessionManager.open` for rename — a pure facade can't intercept
   statics → the one real TUI change (below).

## Protocol additions (P2.1 — server + client + types + tests)

New commands (all thin, key-free testable in rpc-lifecycle style):
`get_context_usage`, `get_system_prompt`, `get_tools`,
`get_resources` (skills/prompts+argumentHint/themes/extensions/agentsFiles/
systemPromptSource/appendSystemPromptSources — the startup "loaded
resources" data), `set_scoped_models`, `navigate_tree`, `reload`,
`export_jsonl`, `abort_compaction`, `abort_branch_summary`, `clear_queue`,
`get_auth_status` (oauthProviders[]), `refresh_models`,
`rename_session` (for picker rename).

Extensions to existing types:
- `RpcSessionState.scopedModels: Array<{model, thinkingLevel?}>`
- `RpcSlashCommand.argumentHint?: string`
- New server event `session_changed` `{sessionId, cwd}` emitted from
  `RpcServer.rebindSession` — this is how the client learns about
  **extension-initiated** session switches (the server rebinds on
  newSession/switch/fork; the event drives the client's rebind flow,
  replacing the in-process `setRebindSession` callback).

## The facade (P2.2/P2.3)

New files under `src/modes/attach/`:

**`remote-agent-session.ts`** — mirror + command delegation:
- Prefetch at attach: `get_state`, `get_entries(+leafId)`,
  `get_resources`, `get_available_models`, `get_auth_status`,
  `get_context_usage`, `get_tools`.
- Mirror updates: events as in finding 4; synchronous mirror updates from
  each mutating command's response; refetch `get_context_usage` on
  `agent_end`/`agent_settled`; full refetch on `session_changed`.
- Sub-facades:
  - `settingsManager` → real local `SettingsManager` (finding 1)
  - `sessionManager` → getCwd (const from hello), getSessionFile/Id/Name
    (mirror), getEntries/getLeafId/getTree (mirror), `buildContextEntries`
    (pure fn over mirror), `usesDefaultSessionDir`→true,
    `appendLabelChange` → friendly no-op v1
  - `modelRuntime` → getAvailable/getAvailableSnapshot/refresh via RPC;
    `isUsingOAuth` from cache; `login/logout/listCredentials/getAuth/
    checkAuth/getProviderAuthStatus/getProviders/getProvider/getModel/
    getError` → friendly degradation where not remotely answerable
  - `extensionRunner` → `getRegisteredCommands` from `get_commands`
    (incl. `argumentHint`); `getMessageRenderer/getEntryRenderer` →
    undefined (extension custom renderers degrade to default rendering —
    they can't cross a wire); diagnostics → empty
  - `resourceLoader` → from `get_resources` (themes included — they're
    JSON, applied client-side, so remote project themes work)
  - `agent` → `signal` (local AbortSignal), `transport` setter no-op v1
  - `executeBash(cmd, onChunk)` → `bash` command + `onChunk` fed by
    matching-id `bash_execution_update` events
  - `state` → synthesized `AgentState` (model/thinkingLevel/messages/
    isStreaming) from mirror; `messages` mirror via `message_end`

**`remote-runtime.ts`** — host + bridges:
- `session` getter; `setRebindSession`/`setBeforeSessionInvalidate` stored
- `newSession/switchSession/fork` → RPC; rebind driven by the
  `session_changed` event: refetch → `beforeSessionInvalidate()` → swap
  mirror → TUI's rebind callback (which rebinds its extension UI context)
- Event router (on client events): `AgentSessionEvent` → session
  listeners; `extension_ui_request` → stored TUI uiContext (finding 6);
  `detached` → shutdown flow (show reason, exit for `--cmd`, return to
  shell for `--sock`); `extension_error` → status line
- `dispose` → `client.stop()` (shutdown for `--cmd`, detach for `--sock`)
- `importFromJsonl` (used by `/import`) → friendly error v1 (client-side
  file path semantics unclear; follow-up)
- `services` (2 uses — exact usage to confirm as task 1 of P2.2),
  `diagnostics: []`, `modelFallbackMessage: undefined`

## Static seams (the only InteractiveMode changes)

`InteractiveModeOptions` gains an optional override:
```ts
sessionPicker?: {
  list(onProgress?): Promise<SessionInfo[]>;
  listAll(onProgress?): Promise<SessionInfo[]>;
  rename?(sessionPath: string, name: string): Promise<void>;
}
```
`showSessionSelector` uses it when present (3 call sites, ~25 lines);
default preserves current static `SessionManager.list/listAll/open`
behavior. Attach provides RPC-backed impls (`list_sessions`,
`list_sessions all`, `rename_session`), mapping ISO dates back to `Date`.

## CLI (P2.5)

`pi attach --cmd '<shell cmd>'` | `pi attach --sock PATH` (subcommand
dispatch like `auth`/`update`):
1. Parse; build local settings/keybindings/theme (client-side stack as
   today).
2. Connect `RpcClient` (`command` transport spawns via `sh -c` — ssh,
   docker exec, `gantry exec proj -- pi --mode rpc`; `socketPath`
   connects).
3. Prefetch (above); construct facades; construct `InteractiveMode` with
   the picker seam; `init()` + `run()`.
4. Exit: `--cmd` → `shutdown` (owns agent); `--sock` → `detach`.
No local session creation, no local project trust flow, no local session
picker at startup (agent-side sessions via the picker seam when wanted).

## Phasing

| Step | Deliverable | Verify |
|---|---|---|
| P2.1 | 14 commands + 2 type extensions + `session_changed` event, server+client | rpc-lifecycle-style tests |
| P2.2 | `RemoteAgentSession` + sub-facades | unit: mirror from synthetic events |
| P2.3 | `RemoteAgentSessionRuntime` + UI bridge + rebind | unit: bridge routing, rebind flow |
| P2.4 | sessionPicker seam | existing suite green |
| P2.5 | `pi attach` CLI | boots headless-ably to construction |
| P2.6 | live iteration vs real socket server (kimi-coding creds) | boot/prompt/footer//model//resume/bash//tree//fork/extension dialogs/detach-reattach |
| P2.7 | tests, docs, plan+RFC status | full suite, biome |

## Known degradations (documented, acceptable for v1)

- `/login`, `/logout`: authenticate on the agent host (OAuth dances are
  host-local by nature)
- Extension custom message/entry renderers → default rendering
- `transport` setting write → no-op (server-side concern)
- `/import` from client-local jsonl → error message
- `appendLabelChange` → no-op (tree labels)
- `fs_complete` for `@` completion: the attach CLI wires the autocomplete
  provider's fd path to the RPC-backed completion instead of local fd
  (exact wiring in P2.5 — `CombinedAutocompleteProvider` takes `fdPath`;
  needs either an RPC-backed fd shim (a tiny script exec'ing
  `fs_complete`) or a provider seam — decide at implementation time)

## Risks

- **Mirror drift**: events are lossy over a dropped connection — mitigated
  by refetch on `session_changed`/`agent_settled` and takeover
  notification; residual staleness is footer-level, not correctness.
- **Inventory surprises**: 5,056 lines may hold dynamic accesses grep
  missed → P2.6 iteration is the safety net; worst case another seam.
- **`services` usage** (2 hits) unexamined → first task of P2.2.
- Effort: ~2–3 focused days equivalent across P2.1–P2.7.
