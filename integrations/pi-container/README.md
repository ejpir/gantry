# pi-attach agent container

Run the pi coding **agent inside a Docker container** and drive it from the
stock host TUI over `pi attach` — the agent-in-guest model with nothing but a
thin client on the host:

```
┌──────────────┐        unix socket (bind-mounted)       ┌────────────────────┐
│ host: pi TUI │ ──────────────────────────────────────▶ │ container: pi agent │
│ pi attach    │ ◀──────── events (stream, UI bridge) ── │  --mode rpc --sock  │
└──────────────┘                                         │  tools, LLM creds,  │
                                                         │  extensions, files  │
                                                         └────────────────────┘
```

Everything sensitive — LLM credentials (`auth.json`), tool execution, file
writes, extension processes — happens **inside** the container. The host runs
only the TUI renderer.

## Prerequisites

- The pi monorepo at `../../../pi` (branch `pi-attach-v1`) — nothing else:
  the image runs `npm ci` + `npm run build:offline` itself, so the host's
  node_modules state and architecture are irrelevant (mac and sandbox can
  share the same checkout safely).
- Docker (Desktop or the sandbox daemon) or podman. The base image comes
  from the corporate Artifactory mirror — Docker Hub is Zscaler-blocked.
- Corp CA certs: staged automatically from
  `/usr/local/share/ca-certificates/` (linux) or the macOS System keychain.

## Platform notes

| | dev sandbox (linux) | macOS |
|---|---|---|
| CLI | `docker --context default` + built-in builder | `docker` or `podman` |
| proxy (build + run) | `gateway.docker.internal:3128` (verified reachable from containers; `192.168.1.1` is NOT) | none (direct egress) |
| default attach | `--sock` (bind mount works) | `--exec` (bind-mounted unix sockets through the mac VM layer are unreliable) |

The build uses `node:24-slim` and `build:offline` (`packages/ai`'s online
build fetches model catalogs).

## Usage

```bash
./pi-container.sh build      # build the pi-attach-agent image
./pi-container.sh run ~/repos/my-project   # start agent; project → /work
./pi-container.sh attach     # host TUI (auto transport per platform)
./pi-container.sh attach --sock   # force bind-mounted socket transport
./pi-container.sh attach --exec   # force container-exec stdio transport
./pi-container.sh logs       # agent container logs
./pi-container.sh stop
```

The socket lands in `/tmp/pi-attach/agent.sock` (0600, umask-protected at
birth). The project directory is mounted read-write at `/work` — file edits
by the agent hit your real checkout, processes run in the container.

## How it works

- The image is a multi-stage build on `node:24-slim`: `npm ci` →
  `npm run build:offline` → `npm prune --omit=dev`, then a slim runtime
  stage with the corp CA bundle (`NODE_EXTRA_CA_CERTS`). The proxy env is
  a build ARG / run-time `-e`, not baked in.
- A minimal `settings.json` (kimi-coding defaults) is baked in; only
  `auth.json` is mounted (read-write, OAuth tokens refresh).
- The agent runs `--mode rpc --sock /sock/agent.sock`; the socket directory
  is bind-mounted so the host TUI connects to it directly.
- `pi attach` gives you the full stock TUI: streaming, `/resume` over the
  container's sessions, `/model`, `/login`/`/logout` (bridged auth flows),
  `/import` (client-side file upload), extension dialogs, bash chunks.
- Exit behavior: closing the TUI **detaches** (agent keeps running, session
  preserved in the container); re-attach any time. `docker stop` → the TUI
  auto-reconnects for 30s if the container restarts.

## Verified (sandbox, v2 platform-independent image)

- `hello` handshake: `protocol 1, version 0.83.0, cwd /work`, capabilities
  `shutdown detach fs_complete read_file list_sessions login logout
  import_session`.
- Pty smoke: prompt submitted from the host TUI → LLM call from inside the
  container → `CONTAINER-V2-OK` streamed back host-side → session JSONL
  persisted in the container.
- Full in-image build behind the sandbox proxy: `npm ci` (registry.npmjs.org
  via `gateway.docker.internal:3128`), `build:offline`, prune.

## Notes / limits

- Sessions live **in the container** (`/home/node/.pi/agent/sessions`); mount
  a volume there if you want them to survive `stop`.
- Container node runs as uid 1000 (`node`); on this sandbox that maps to the
  `agent` user, so socket + `/work` permissions line up.
- The `exec` attach path spawns a *second* pi inside the container over
  docker-exec stdio (per-attach agent, shutdown on exit) — handy when the
  socket is not mounted.
- Native modules (`ssh2`, `cpu-features`) build inside the image; without
  a toolchain they fall back to pure-JS paths (npm tolerates their failure
  as optional deps).
