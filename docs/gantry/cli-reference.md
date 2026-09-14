# Gantry CLI reference

This page summarizes the public command surface. Run `gantry --help` and
`gantry start --help` for the exact defaults and resource limits of your
installed build.

## Sandbox lifecycle

### `gantry start`

Create and boot a persistent sandbox:

```text
gantry start NAME [flags]
```

Names accept letters, digits, `.`, `_`, and `-`, up to 64 characters.

Common flags:

| Flag | Description |
|---|---|
| `-image SOURCE` | OCI reference, OCI layout/archive, Docker save archive, or EROFS file |
| `-cpus N` | Guest virtual CPU count |
| `-mem MIB` | Guest memory in MiB |
| `-disk-size MIB` | Initial private writable-layer size |
| `-runtime MODE` | Guest OCI runtime: `crun` or `runsc` |
| `-rw=false` | Disable the writable container overlay |
| `-share SPEC` | Add a host-directory share; repeatable |
| `-secret SPEC` | Inject `NAME` from the launcher environment or `NAME=@/canonical/path` from an existing symlink-free single-link file; append `@host` for broker-only delivery and `,ttl=60s` for refresh; command sources are refused |
| `-secret-file PATH` | Load a symlink-free single-link dotenv file; repeatable |
| `-net=false` | Disable guest networking |
| `-net-policy PATH` | Load a JSON egress policy |
| `-allow-local-net` | Allow host, LAN, link-local, and related destinations |
| `-p SPEC`, `-publish SPEC` | Publish a host port; repeatable |
| `-proxy URL` | Set an HTTP(S) or SOCKS upstream proxy |
| `-no-proxy LIST` | Override the proxy bypass list |
| `-proxy-enforce` | Block direct TCP 80/443 and UDP 443 except to the proxy |
| `-oauth-bridge=false` | Disable automatic guest-loopback OAuth callback bridging |
| `-oauth-custody` | Hold OAuth tokens on the host (Codex, Claude, GitHub, and configured public-client providers) |
| `-oauth-provider PATH` | Snapshot a host-owned OAuth provider JSON file; repeatable, requires `-oauth-custody` ([configuration](shares-secrets.md#custom-providers-and-mcp-servers)) |
| `-mcp` | Enable the MCP gateway with the contained read-only filesystem server ([manual](mcp-gateway.md)) |
| `-mcp-fs-root PATH` | Confine the MCP filesystem server to PATH (default `/`) |
| `-mcp-fs-user USER` | Run MCP local servers as this guest user (name, numeric UID from passwd, or explicit `UID:GID`; default `nobody`; root refused) |
| `-mcp-remote SPEC` | Add a remote streamable-HTTP MCP server: `name=ID,url=URL[,auth=bearer:SECRET\|header:NAME:SECRET\|custody:PROVIDER][,allow=GLOB][,deny=GLOB][,redact=SECRET]`; repeatable |
| `-ssh` | Enable the sandbox-local SSH protocol endpoint (off by default; no TCP listener) |
| `-devcontainers` | Add the curated IDE peer container and nested Podman; preserves `-image` as the workload |
| `-process-isolation MODE` | `auto`, `required`, or `off` |

Advanced boot flags are `-kernel`, `-rootfs`, `-rwlayer`, and `-layerset`.
The legacy external `-gvproxy` backend is disabled because it launches a
configurable host executable; use the embedded network stack.

### `gantry configure`

Persist SSH, Dev Containers, and resource settings on an existing sandbox:

```text
gantry configure NAME [--ssh[=BOOL]] [--devcontainers[=BOOL]]
                      [--mem MIB] [--cpus N] [--process-isolation MODE]
```

SSH can apply immediately. Memory, CPU, process-isolation, and Dev Containers
topology changes apply on the next VM start. Add `-remote PROFILE` to update
that manager's sandbox instead; no local fallback is allowed. Remote updates
accept `-key KEY` for safe retries, preserve omitted flags and explicit false,
and return whether a running VM needs restarting.

### `gantry exec`

Run a disposable sandbox:

```text
gantry exec [start flags] [-- COMMAND ARG...]
```

Use `-console` to mirror the guest serial console to stderr. Without an
explicit command, Gantry uses the image entrypoint and command, then
`/bin/sh` as a fallback.

Execute in a running named sandbox:

```text
gantry exec NAME [-- COMMAND ARG...]
```

Named attach mode accepts no execution flags. It detects an interactive
terminal automatically.

### `gantry ls`

List running and stopped sandboxes:

```text
gantry ls
```

### `gantry stop`

Gracefully stop a running sandbox while preserving configuration and disk:

```text
gantry stop NAME
```

### `gantry resume`

Boot a stopped sandbox from `sandbox.json`:

```text
gantry resume NAME
```

Secret values must be present again in Gantry's environment.

### `gantry delete`

Stop and remove a sandbox and its Gantry-managed default writable layer:

```text
gantry delete NAME
```

Shared host directories, cached images, and an explicitly supplied `-rwlayer`
are not deleted.

### `gantry export`

Package a stopped sandbox's immutable base and persistent overlay changes as a
portable OCI image-layout archive:

```text
gantry export [--name REF] [-o OUTPUT] [--force] NAME [OUTPUT]
```

The output defaults to `NAME.oci.tar`, and its embedded local reference
defaults to `gantry-export/<normalized-name>:latest`. The sandbox must be
stopped so the writable ext4 filesystem is consistent. Host shares are not
copied. The archive can contain credentials or other sensitive files
persisted by guest programs and is therefore created with mode `0600`.

Import it on another host with `gantry image import ARCHIVE`, then use the
reported local reference with `gantry start -image`.

## SSH access

```text
gantry ssh NAME [-- COMMAND ...]
gantry ssh doctor NAME
gantry ssh setup [--remove]
```

`gantry ssh` uses stock OpenSSH through the private per-sandbox socket. The
hidden `ssh-proxy` and `ssh-known-hosts` commands are used by OpenSSH client
configuration and should not normally be invoked directly. `-devcontainers`
adds a curated IDE peer container with nested Podman inside the same sandbox
VM; it preserves the workload selected by `-image` and never exposes a host
container engine. See [SSH access](ssh-access.md).

## Images

```text
gantry image ls
gantry image pull [-platform linux/ARCH] SOURCE
gantry image import [-platform linux/ARCH] [-name REF] ARCHIVE_OR_OCI_LAYOUT
gantry image rm REF_OR_DIGEST
gantry image prune
gantry image login REGISTRY [-u USER] [--password-stdin]
gantry image logout REGISTRY
gantry image credentials [REGISTRY...]
```

`import` stores an OCI layout/archive or Docker save archive under its embedded
reference. Pass `-name` when the source has no reference or to override it.
`prune` removes every cached digest not referenced by saved sandbox state.

## Host shares

```text
gantry share add [--replace] [--ephemeral] NAME SHARE_SPEC
gantry share remove [--force] [--ephemeral] NAME TAG
gantry share ls NAME
```

Share grammar:

```text
TAG=HOST_PATH[@CONTAINER_PATH][,ro][,uid=N,gid=N]
```

Persistent live changes update `sandbox.json`; `--ephemeral` affects only the
current boot.

## Published ports

```text
gantry ports ls NAME
gantry ports publish [--ephemeral] NAME PORT_SPEC
gantry ports unpublish [--ephemeral] NAME PORT_SPEC
```

Port grammar:

```text
[HOST_IP:]HOST_PORT:GUEST_PORT[/udp]
GUEST_PORT
```

The one-field form chooses a free host port. TCP is the default protocol and
host loopback is the default bind address. UDP publishes require an egress
policy that permits every virtual-gateway reply port in
`192.168.127.1:16000-65535/udp`; the default policy rejects them.

## Network policy

```text
gantry net-policy set [--allow-local-net] NAME POLICY.json
gantry net-policy default [--allow-local-net] NAME
gantry net-policy show NAME
```

`set` and `default` apply live to compatible running sandboxes and persist for
the next boot.

## Organization policy

```text
gantry policy generate -out DIR [-mount PATH ...] [-ttl 30d] [-profile developer]
gantry policy sign -data data.json -out DIR (-signing-key private.pem | -ephemeral)
gantry policy verify -bundle bundle.tar.gz -key public.pem -profile NAME
gantry policy check -bundle bundle.tar.gz -key public.pem -profile NAME -action ACTION -resource JSON
gantry policy set NAME -bundle bundle.tar.gz -key public.pem -profile NAME
gantry policy show NAME
gantry policy clear NAME
```

`generate` creates a restrictive test policy: default-deny except for explicit
read-only mount roots. It also accepts `-organization` and `-revision`; defaults
are `local-test` and a timestamp. TTL supports whole days or Go-style durations
from 1 second through 365 days. `sign` validates and signs edited JSON without
changing its permissions, revision, or expiry.

Both authoring commands require a **new output directory**, containing
`source/data.json`, `bundle.tar.gz`, and `public.pem`. They never save private keys.
`generate` and `sign -ephemeral` use fresh test keys; `sign -signing-key` uses an
existing RSA private key. No OPA/OpenSSL installation is required. `set` and
`clear` require a stopped sandbox. See [Organization policy](organization-policy.md)
for the workflow and [Architecture](architecture.md#organization-policy-engine)
for supported rules and security limits.

## Organization login

```text
gantry org login -config organization.json [-profile NAME] [-no-browser] [-timeout 5m]
gantry org status ORGANIZATION
gantry org apply ORGANIZATION SANDBOX
gantry org logout ORGANIZATION
```

Uses OIDC Authorization Code + S256 PKCE with a trusted HTTPS issuer and explicit
membership-to-profile mappings. Only a token-free host receipt and pinned signed
policy are saved. `apply` requires an active login and a stopped sandbox without
OAuth custody. Logout/login expiry do not revoke already-pinned policies or end
provider SSO. See [Organization login](organization-login.md) to get started and
[Architecture](architecture.md#organization-identity-and-discovery) for trust
configuration, protocol details and validation.

## Security audit trail

```text
gantry audit NAME
```

Prints the sandbox daemon's trail of security-relevant events: organization
policy decisions, credential deliveries and withholds, secret-source failures,
and OAuth custody events (logins, refreshes, push failures). Uses the live ring
while running and falls back to `audit.log` after shutdown. The trail names
secrets but never quotes values, and returns at most 256 retained events.
Persistence is bounded and best-effort, not a compliance archive. `daemon.log`
remains the primary record.

## Dashboard

Open the dashboard by running `gantry` with no arguments in an interactive
terminal, or explicitly:

```text
gantry tui
```

Press `?` inside the dashboard for key bindings.

Press `A` (or use Tab) to open **Audit**. It refreshes automatically and shows
live events or the saved trail for stopped sandboxes. Policy decisions highlight
allow/deny, action, reason, organization, revision, profile, and matching rule IDs.
Use `/` to filter by sandbox, `S` or column headers to sort, `r` to refresh, and
Enter to inspect/copy the full recorded event. The default order is newest first
within each sandbox; the audit format has no timestamps. This view is read-only.

## Manager API

```text
gantry serve [-socket PATH]
gantry serve -listen tls://ADDR:PORT --token-file FILE [--self-signed]
```

The default endpoint is `~/.gantry/manager.sock`. See
[Manager API](manager-api.md).

## Remote managers

A manager served with `-listen tls://…` is a remote control plane for the
everyday verbs. Profiles are configured once and selected per command:

```text
gantry remote add NAME https://HOST:PORT [--token-file FILE | --token-stdin]
             [--ca FILE] [--fingerprint sha256:HEX]
gantry remote ls
gantry remote test NAME
gantry remote rm NAME

gantry start dev -image alpine:latest -remote NAME
gantry exec dev -remote NAME -- uname -a
gantry ls -remote NAME
gantry stop dev -remote NAME
gantry resume dev -remote NAME
gantry delete dev -remote NAME
```

`GANTRY_REMOTE` supplies the default target; an explicit `-remote` wins, and
`-remote ""` forces local. Tokens are host-shell authority on the remote and
are stored in per-remote `0600` files under `~/.gantry/remotes/`; a
group/world-readable token file is refused. TLS is always verified — pass
`--ca` for servers using `--self-signed` (the server's
`~/.gantry/serve/ca.crt`) and `--fingerprint` to pin the exact certificate
printed by `gantry serve` at startup. Remote exec is non-interactive
(bounded output, guest exit code propagated); use `gantry ssh NAME -remote
PROFILE` for a terminal. Paths in start flags (`-share`, `-net-policy`,
`-kernel`, …) resolve on the remote host. Organization bundle/key flags instead
upload local signed policy files. `-secret` accepts plain names resolved from
the manager's own environment.

Remote image pulls, SSH, live events, policy changes, and audit tails are also
supported. CLI start requires a cached image: run `gantry image pull REF -remote
NAME` first. The TUI's **Create → Local / Remote / Organization** flow can pull
missing images remotely and offers standalone registration without org login.
**Remotes (B)** supports **a** add, **t** test, **d** remove profile/token, and
**L** organization sign-in/discovery. See [Remote access](remote-access.md) for
examples, security boundaries and the catalog contract.

## Coding-agent helpers

Run Pi in a per-project sandbox:

```text
gantry pi [flags] [-- PI_ARGS]
```

Flags include `-image`, `-net-policy`, `-mem`, `-cpus`, `-secret`,
`-pi-auth=false`, and `-restart`.

Run or reuse the experimental guest Pi RPC bridge and print the host attach
command:

```text
gantry pi-serve [flags]
```

See [Coding agents](coding-agents.md).

## Import a Docker sandbox

Discover stopped sandboxes from the reference Docker Sandboxes state:

```text
gantry import
```

Preview or adopt one:

```text
gantry import NAME --dry-run
gantry import NAME [-as NEW_NAME] [-workspace-owner auto|host|UID:GID]
```

Advanced flags `-root` and `-log` override the source daemon state and log
paths. The source sandbox must be quiescent. Gantry attaches its immutable
EROFS layer set without pulling or flattening and clones the writable ext4
layer privately before starting the adopted sandbox.

## Low-level VMM

`gantry run` is an advanced interface that boots explicit kernel and disk
assets without creating managed sandbox state:

```text
gantry run -kernel PATH (-initrd PATH | -rootfs PATH) [flags]
```

It accepts extra `-disk` and `-share` values, memory and vCPU settings, a raw
network endpoint, and virtio-vsock forwarding options. Prefer `start` and
`exec` for OCI workloads.

With `-remote PROFILE`, those same raw boot paths resolve on the manager host.
Remote-only flags are `-timeout SECONDS` (default 300, maximum 3600),
`-max-output BYTES` (default 16384, maximum 65536), and `-key KEY` for idempotent
retries. Console input/output is bounded and noninteractive. Exit 124 means the
helper reached its deadline; exit 130 means cancellation. This does not create
a named sandbox and is not an alias for `start`. See [Remote access](remote-access.md).

## Version and updates

```text
gantry version
gantry update
gantry update --force   # reinstall a deliberately rebuilt/retagged release
```

## Environment variables

| Variable | Purpose |
|---|---|
| `GANTRY_ARTIFACTS` | Explicit guest-asset directory |
| `GANTRY_HOME` | Sandbox-state root instead of `~/.gantry/sandboxes` |
| `GANTRY_REMOTE` | Default `-remote` target for lifecycle verbs |
| `GANTRY_IMAGES` | OCI image-cache root instead of `~/.gantry/images` |
| `GANTRY_RUNTIME` | Default guest runtime for `start` and one-shot `exec` |
| `GANTRY_PI_IMAGE` | Default image for `gantry pi` |

Additional `GANTRY_*` variables exist for development diagnostics and test
harnesses. They are not part of the normal user interface.
