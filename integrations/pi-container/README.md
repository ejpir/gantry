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

- The pi monorepo at `../../../pi` (branch `pi-attach-v1`), with
  `npm install` and `npm run build` done **on linux/arm64** (the sandbox).
- Docker access via the `default` context (the corporate Artifactory mirror
  `nn-docker-remote.artifactory.insim.biz` is used for the base image —
  Docker Hub is Zscaler-blocked).
- Corp CA certs in `/usr/local/share/ca-certificates/` (staged at build time)
  and the HTTP proxy reachable at `192.168.1.1:3128` for LLM egress.

## Usage

```bash
./pi-container.sh build      # build the pi-attach-agent image
./pi-container.sh run ~/repos/my-project   # start agent; project → /work
./pi-container.sh attach     # host TUI over the bind-mounted socket
./pi-container.sh exec       # alternative: attach over docker-exec stdio
./pi-container.sh logs       # agent container logs
./pi-container.sh stop
```

The socket lands in `/tmp/pi-attach/agent.sock` (0600, umask-protected at
birth). The project directory is mounted read-write at `/work` — file edits
by the agent hit your real checkout, processes run in the container.

## How it works

- The image is `node:22-slim` + the pre-built monorepo (`dist/` +
  `node_modules`, no npm install in the build) + corp CA bundle
  (`NODE_EXTRA_CA_CERTS`) + proxy env (`HTTPS_PROXY=192.168.1.1:3128`).
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

## Verified

- `hello` handshake: `protocol 1, version 0.83.0, cwd /work`, capabilities
  `shutdown detach fs_complete read_file list_sessions login logout
  import_session`.
- Pty smoke: prompt submitted from the host TUI → LLM call from inside the
  container via proxy+Zscaler CA → streamed reply rendered host-side →
  session JSONL persisted in the container.

## Notes / limits

- Sessions live **in the container** (`/home/node/.pi/agent/sessions`); mount
  a volume there if you want them to survive `stop`.
- Container node runs as uid 1000 (`node`); on this sandbox that maps to the
  `agent` user, so socket + `/work` permissions line up.
- The `exec` attach path spawns a *second* pi inside the container over
  docker-exec stdio (per-attach agent, shutdown on exit) — handy when the
  socket is not mounted.
- Native modules (`ssh2`, `cpu-features`) are copied from the sandbox's
  linux/arm64 install; on a glibc-incompatible host, `npm rebuild` them
  inside the build.
