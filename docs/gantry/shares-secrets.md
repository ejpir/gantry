# Host shares and secrets

Shares expose selected host directories. Secrets provide credentials without
putting literal values in command arguments or `sandbox.json`.

## Share a host directory

```console
$ gantry start dev -image alpine:latest \
    -share "code=$PWD,mount=/workspace"
```

Share syntax:

```text
TAG=HOST_PATH[,mount=CONTAINER_PATH][,ro][,uid=N,gid=N]
```

| Part | Meaning |
| --- | --- |
| `TAG` | Name used by `gantry share` commands. |
| `HOST_PATH` | Existing host directory. |
| `mount` | Absolute container path; defaults to `/host/TAG`. |
| `ro` | Read-only host export. |
| `uid`, `gid` | Guest-visible numeric owner; use both together. |

Use `,ro` whenever write access is unnecessary:

```console
$ gantry start review -image alpine:latest \
    -share "source=$PWD,mount=/workspace,ro"
```

Read-only enforcement happens at the host export. `uid` and `gid` change only
the ownership shown to the guest; they do not run `chown` on the host.

> [!WARNING]
> A writable share grants the guest your access within that directory. Do not
> share a home directory, credential store, container-engine socket, or Gantry
> state directory with untrusted code.

For a host path containing reserved grammar text, use base64url encoding:

```text
code=L3RtcC9wcm9qZWN0QC9zdWJkaXI,encoding=base64url
```

This example represents `/tmp/project@/subdir`.

## Change shares while running

```console
$ gantry share add dev "docs=$PWD/docs,mount=/reference,ro"
$ gantry share add --replace dev "docs=$PWD/new-docs,mount=/reference,ro"
$ gantry share ls dev
$ gantry share remove dev docs
```

Changes persist unless `--ephemeral` is used. Removal waits for open handles;
use `--force` only when immediate revocation is more important than clean guest
I/O.

Windows shares must be local NTFS directories. UNC, removable, network, and
non-NTFS roots are unsupported.

To read a share through the built-in MCP filesystem server, use the same guest
path as `-mcp-fs-root` and choose an MCP user with read permission. See
[MCP gateway](mcp-gateway.md#read-a-mounted-workspace-through-mcp).

## Inject secrets

Pass the name of an environment value:

```console
$ export GITHUB_TOKEN=...
$ gantry start agent -image alpine:latest -secret GITHUB_TOKEN
```

Or use an existing host file:

```console
$ gantry start agent -image alpine:latest \
    -secret GITHUB_TOKEN=@/secure/token
```

Load several values from a dotenv file with repeatable `-secret-file` flags.
Later definitions of the same name win.

Gantry refuses `-secret NAME=literal`; argv and shell history are not private.
An ordinary secret becomes a guest environment variable, so guest code can
read, write, or send it anywhere allowed. Pair sensitive values with narrow
shares and a [default-deny network policy](networking.md#define-an-egress-policy).

## Refreshable secret sources

File values can rotate while a sandbox runs:

```console
$ gantry start agent -image alpine:latest \
    -secret GITHUB_TOKEN=@/secure/token,ttl=60s
```

Environment values are captured at start. File values default to a 60-second
cache; `ttl=0` reads on every use. If a source disappears or becomes unsafe,
Gantry drops the cached value and fails closed.

A file source must be an absolute, clean path to an existing single-link
regular file, without symlinks or Windows reparse points. It cannot be inside
or alias a writable share. Command-backed secret sources are disabled.

See [Architecture](architecture.md#mcp-and-credential-flow) for source pinning,
refresh, and broker internals.

## Bind a secret to a host

Append `@host` to keep a credential out of guest environments:

```console
$ gantry start agent -image alpine:latest \
    -secret GITHUB_TOKEN@github.com=@/secure/token,ttl=60s
```

The guest git credential helper can request the value only for that host and
only when network policy allows it. Wildcards such as
`@*.githubusercontent.com` match subdomains. Deliveries and refusals are
recorded by secret name in `gantry audit`; values are omitted.

Bound secrets can also authenticate remote MCP servers. See
[MCP gateway](mcp-gateway.md#choose-remote-credentials).

## Secret lifecycle

`sandbox.json` stores names and source references, never values.

- Export environment values again before `gantry resume`.
- File references resolve again on resume.
- Dotenv and dashboard values are memory-only and must be supplied again.
- Removing a secret affects the next use; already delivered values cannot be
  recalled.

Registry credentials use the host image puller instead. See
[Images](images.md#registry-credentials).

For browser login and host-held refresh tokens, see [OAuth](oauth.md).
