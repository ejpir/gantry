# Gantry CLI reference

This page lists the public command surface. Run `gantry --help` and
`gantry COMMAND --help` for exact defaults, limits, and advanced flags.

## Sandbox lifecycle

### `gantry apply` and `gantry manifest`

```text
gantry manifest validate FILE
gantry manifest export NAME
gantry apply -f FILE [--check] [--force]
```

Manifests are strict, versioned YAML sandbox definitions. `apply` creates and
starts a missing sandbox, resumes an unchanged stopped sandbox, and cleanly
restarts a changed running sandbox. `--check` reports the action without
changing state. `export` emits a redacted, re-applicable manifest and never
includes secret values. See [Sandbox manifests](manifests.md).

### `gantry start`

```text
gantry start NAME [flags]
```

Names use letters, digits, `.`, `_`, or `-`, up to 64 characters.

Common flags:

| Flag | Purpose |
|---|---|
| `-image SOURCE` | OCI reference/layout/archive, Docker save archive, or EROFS file |
| `-cpus N`, `-mem MIB` | VM CPU and memory |
| `-disk-size MIB` | Initial private writable-disk size |
| `-runtime crun\|runsc` | Guest OCI runtime |
| `-rw=false` | Read-only container root |
| `-share SPEC` | Host directory share; repeatable |
| `-secret SPEC`, `-secret-file PATH` | Guest secret sources |
| `-net=false`, `-net-policy PATH` | Disable or restrict networking |
| `-allow-local-net` | Permit host and LAN destinations |
| `-p SPEC`, `-publish SPEC` | Host-to-guest port; repeatable |
| `-proxy URL`, `-no-proxy LIST`, `-proxy-enforce` | Upstream proxy settings |
| `-oauth-bridge=false` | Disable guest browser-login callback bridging |
| `-oauth-custody`, `-oauth-provider PATH` | Host-held OAuth tokens and custom providers |
| `-mcp`, `-mcp-fs-root PATH`, `-mcp-fs-user USER` | Built-in MCP filesystem server |
| `-mcp-remote SPEC` | Remote MCP server; repeatable |
| `-ssh` | Private sandbox SSH gateway |
| `-devcontainers` | Curated IDE environment with nested Podman |
| `-process-isolation auto\|required\|off` | Worker isolation mode |

Advanced boot flags include `-kernel`, `-rootfs`, `-rwlayer`, and `-layerset`.
See the topic guides for complete value formats.

### `gantry configure`

```text
gantry configure NAME [--ssh[=BOOL]] [--devcontainers[=BOOL]]
                      [--mem MIB] [--cpus N] [--process-isolation MODE]
```

SSH may change live. VM resources, process isolation, and Dev Containers may
require a stop and resume. Add `-remote PROFILE` and optional `-key KEY` for a
remote update.

### `gantry exec`

Create a disposable sandbox:

```text
gantry exec [start flags] [-- COMMAND ARG...]
```

Run in an existing sandbox:

```text
gantry exec NAME [-- COMMAND ARG...]
```

Named attach mode accepts no execution flags. Without a command, Gantry uses
the image defaults, then `/bin/sh`.

### List, stop, resume, and delete

```text
gantry ls
gantry stop NAME
gantry resume NAME
gantry delete NAME
```

Stop preserves state. Delete removes Gantry-managed sandbox state and writable
layers, but not shares, cached images, or a caller-owned `-rwlayer`.

### `gantry export`

```text
gantry export [--name REF] [-o OUTPUT] [--force] NAME [OUTPUT]
```

The sandbox must be stopped. Host shares and the Dev Containers disk are not
included. See [Images](images.md#export-and-import-a-sandbox).

## Images

```text
gantry image ls
gantry image pull [-platform linux/ARCH] SOURCE
gantry image import [-platform linux/ARCH] [-name REF] ARCHIVE_OR_LAYOUT
gantry image rm REF_OR_DIGEST
gantry image prune
gantry image login REGISTRY [-u USER] [--password-stdin]
gantry image logout REGISTRY
gantry image credentials [REGISTRY...]
```

`prune` keeps digests referenced by saved sandboxes.

## Shares and ports

```text
gantry share add [--replace] [--ephemeral] NAME SHARE_SPEC
gantry share remove [--force] [--ephemeral] NAME TAG
gantry share ls NAME
```

```text
TAG=HOST_PATH[,mount=CONTAINER_PATH][,ro][,uid=N,gid=N]
```

```text
gantry ports ls NAME
gantry ports publish [--ephemeral] NAME PORT_SPEC
gantry ports unpublish [--ephemeral] NAME PORT_SPEC
```

```text
[HOST_IP:]HOST_PORT:GUEST_PORT[/udp]
GUEST_PORT
```

A one-field port chooses a free host port. TCP and host loopback are defaults.
See [Host shares and secrets](shares-secrets.md) and
[Networking](networking.md#publish-ports).

## Network policy

```text
gantry net-policy set [--allow-local-net] NAME POLICY.json
gantry net-policy default [--allow-local-net] NAME
gantry net-policy show NAME
```

Changes persist and apply live when supported.

## Organization policy

```text
gantry policy generate -out DIR [-mount PATH ...] [-ttl 30d]
gantry policy sign -data data.json -out DIR (-signing-key KEY | -ephemeral)
gantry policy verify -bundle BUNDLE -key PUBLIC_KEY -profile PROFILE
gantry policy check -bundle BUNDLE -key PUBLIC_KEY -profile PROFILE -action ACTION -resource JSON
gantry policy set NAME -bundle BUNDLE -key PUBLIC_KEY -profile PROFILE [--restart]
gantry policy show NAME
gantry policy clear NAME [--restart]
gantry policy keygen -out DIR [-bits 3072]
gantry policy feed-request -out DIR -host NAME
gantry policy-service init -dir DIR -organization ORG -url https://HOST:PORT -public-key KEY
                           [-ring NAME ...] [-name TLS_NAME ...]
gantry policy-service serve -dir DIR [-listen ADDR:PORT]
gantry policy-service admin add|rm -dir DIR -name NAME
```

`set` and `clear` apply live to running sandboxes. `--restart` explicitly
requests controlled stop/update/resume instead. `feed-request` creates a
host's policy-feed key and certificate request; `policy-service` runs the
organization's feed and administrator API. See
[Organization policy](organization-policy.md#run-a-policy-service).

## Organization login

```text
gantry org login -config organization.json [-profile NAME] [-no-browser] [-timeout 5m]
gantry org status ORGANIZATION
gantry org remotes ORGANIZATION
gantry org apply ORGANIZATION SANDBOX
gantry org logout ORGANIZATION
```

`apply` requires a current receipt and applies live when the sandbox is
running. See [Organization login](organization-login.md).

## MCP and OAuth

```text
gantry mcp NAME
gantry mcp tools NAME
```

The first shows saved server configuration; the second probes effective tools
in a running sandbox. See [MCP gateway](mcp-gateway.md).

OAuth login runs through the guest helper:

```text
gantry-guest oauth login PROVIDER
```

Configure custom providers with repeatable `-oauth-provider PATH` at start.
See [OAuth](oauth.md).

## SSH

```text
gantry ssh NAME [-- COMMAND ...]
gantry ssh doctor NAME
gantry ssh setup [--remove]
```

SSH uses the private sandbox gateway. See [SSH and Dev Containers](ssh-access.md).

## Audit and dashboard

```text
gantry audit NAME
gantry tui
```

Audit returns a bounded security-event tail and omits values and payloads. Run
`gantry` with no command in an interactive terminal to open the dashboard.
Press `?` inside it for keys.

## Manager and remote access

```text
gantry serve [-socket PATH] [-policy-feed CONFIG]
gantry serve -listen tls://ADDR:PORT --token-file FILE [--self-signed]
             [-policy-feed CONFIG]
```

`-policy-feed` adds one organization-wide outbound mTLS policy receiver. Each
accepted generation applies to all saved sandboxes, and later manager-created
sandboxes inherit it. See
[Organization policy](organization-policy.md#receive-policy-updates).

See [Manager API](manager-api.md).

```text
gantry remote add NAME https://HOST:PORT [--token-file FILE | --token-stdin]
             [--ca FILE] [--fingerprint sha256:HEX]
gantry remote ls
gantry remote test NAME
gantry remote rm NAME
```

Remote-capable commands are `start`, `run`, `configure`, `exec`, `ls`, `stop`,
`resume`, `delete`, `image`, `ssh`, `events`, `net-policy`, `policy`, and
`audit`. Organization-policy changes apply live; `policy set` and `policy
clear` accept `--restart` for a controlled update. Select a profile with
`-remote NAME` or `GANTRY_REMOTE`;
`-remote=""` forces local. There is no failure fallback to local.

Remote CLI start is cache-only; run `gantry image pull REF -remote NAME` first.
Most paths resolve on the manager host. MCP, OAuth custody, layer sets, and
secret files are local-only. See [Remote access](remote-access.md).

## Coding-agent helpers

```text
gantry pi [flags] [-- PI_ARGS]
gantry pi-serve [flags]
```

See [Coding agents](coding-agents.md).

## Import a Docker sandbox

```text
gantry import
gantry import NAME --dry-run
gantry import NAME [-as NEW_NAME] [-workspace-owner auto|host|UID:GID]
```

The source sandbox must be stopped. Gantry reuses immutable EROFS layers and
clones the writable ext4 layer.

## Low-level VMM

```text
gantry run -kernel PATH (-initrd PATH | -rootfs PATH) [flags]
```

This boots explicit assets without managed sandbox state. Prefer `start` or
`exec` for OCI workloads. Remote run adds bounded timeout/output and
idempotency options.

## Version and updates

```text
gantry version
gantry update
gantry update --force
```

Use `--force` only for a deliberately rebuilt release tag.

## Environment variables

| Variable | Purpose |
|---|---|
| `GANTRY_ARTIFACTS` | Explicit guest-asset directory |
| `GANTRY_HOME` | Sandbox-state root |
| `GANTRY_IMAGES` | OCI image-cache root |
| `GANTRY_REMOTE` | Default remote profile |
| `GANTRY_RUNTIME` | Default guest runtime |
| `GANTRY_PI_IMAGE` | Default `gantry pi` image |

Other `GANTRY_*` variables are development and test controls, not normal user
configuration.
