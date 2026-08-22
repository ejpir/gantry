# Host shares and secrets

Host shares give a sandbox access to selected directories. Secrets supply
credentials from the host without putting literal values in command arguments
or persistent sandbox configuration.

## Share a host directory

Share the current project at `/host/code`:

```console
$ gantry start dev -image alpine:latest \
    -share "code=$PWD"
```

Choose another path inside the container with `@`:

```console
$ gantry start dev -image alpine:latest \
    -share "code=$PWD@/workspace"
```

A share specification has this form:

```text
TAG=HOST_PATH[@CONTAINER_PATH][,ro][,uid=N,gid=N]
```

| Part | Meaning |
| --- | --- |
| `TAG` | Name used by `gantry share` commands. |
| `HOST_PATH` | Existing directory on the host. |
| `CONTAINER_PATH` | Absolute guest-container path; defaults to `/host/TAG`. |
| `ro` | Make the export read-only. |
| `uid`, `gid` | Replace the numeric owner shown in the guest. Use both together. |

To make a share readable through Gantry's built-in filesystem MCP server,
set its MCP filesystem root to the share's container path—for example,
`/workspace` for `@/workspace` or `/host/code` for the default `code` mount.
The MCP filesystem user must also have read permission. Remote MCP servers do
not receive direct access to guest mounts. See
[MCP gateway: Read a mounted workspace through MCP](mcp-gateway.md#read-a-mounted-workspace-through-mcp).

## Make a share read-only

Append `,ro` when the workload only needs to inspect files:

```console
$ gantry start review -image alpine:latest \
    -share "source=$PWD@/workspace,ro"
```

Read-only enforcement happens at the host export, not only at the guest mount.

> [!WARNING]
> A read-write share grants the guest the launching user's access within that
> directory. Share the smallest directory the workload needs. Do not share a
> home directory, credential store, or container-engine socket with untrusted
> code.

## Map guest-visible ownership

Use `uid` and `gid` when the image runs as a non-root account:

```console
$ gantry start dev -image node:latest \
    -share "code=$PWD@/workspace,uid=1000,gid=1000"
```

This changes the numeric owner presented to the guest. It does not call
`chown` on the host directory.

## Change shares on a running sandbox

Add and inspect a share:

```console
$ gantry share add dev "docs=$PWD/docs@/reference,ro"
$ gantry share ls dev
```

Replace a tag or remove it:

```console
$ gantry share add --replace dev "docs=$PWD/new-docs@/reference,ro"
$ gantry share remove dev docs
```

Live changes are saved in `sandbox.json` and return after the export becomes
visible or is removed. Add `--ephemeral` to affect only the current boot.
A normal remove waits for open handles to drain; use `--force` when a workload
will not release them.

Linux and macOS propagate host filesystem notifications into guest caches.
Windows supports local NTFS directories and uses conservative cache behavior;
UNC, network, removable, and non-NTFS roots are not supported.

## Inject secrets

Export a value on the host and name it on the Gantry command line:

```console
$ export GITHUB_TOKEN=...
$ gantry start agent -image alpine:latest -secret GITHUB_TOKEN
$ gantry exec agent -- sh -lc 'test -n "$GITHUB_TOKEN"'
```

Read from a host file instead:

```console
$ gantry start agent -image alpine:latest \
    -secret GITHUB_TOKEN=@/secure/token
```

Load several values from a dotenv-style file:

```console
$ gantry start agent -image alpine:latest \
    -secret-file /secure/agent.env
```

Repeat `-secret` and `-secret-file` as needed. A later definition of the same
name wins.

Gantry refuses `-secret NAME=literal`. Values placed in argv can be exposed by
process inspection and shell history.

> [!IMPORTANT]
> An ordinary secret becomes an environment variable for guest processes and
> can be read by code running as that guest user. Pair sensitive secrets with
> a default-deny [network policy](networking.md#define-an-egress-policy) and
> narrow host shares.

## Refreshable secret sources

File and command sources can rotate while a sandbox is running:

```console
$ gantry start agent -image alpine:latest \
    -secret GITHUB_TOKEN=@/secure/token,ttl=60s
```

```console
$ gantry start agent -image alpine:latest \
    -secret GITHUB_TOKEN='!gh auth token'
```

A command source is an argv executed directly on the host, not a shell string.
It can call tools such as `op`, `pass`, or `gh` without vendor-specific Gantry
integration.

The optional `ttl` controls resolved-value caching:

| Source | Default cache | Behavior |
| --- | --- | --- |
| Environment | Start-time snapshot | Read from the launcher once; export again before resume. |
| File | 60 seconds | Read the file again after the TTL. |
| Command | 5 minutes | Run the command again after the TTL. |
| File or command with `ttl=0` | No cache | Resolve on every use. |

If a file disappears or a command fails after previously working, Gantry drops
the cached value and fails closed. It does not serve the stale credential.

## Bind a secret to a host

Append `@host` when a credential should be delivered only through the host
credential broker:

```console
$ export GITHUB_TOKEN=...
$ gantry start agent -image alpine:latest \
    -secret GITHUB_TOKEN@github.com
```

A bound secret is not added to the guest environment. Gantry configures its
guest git credential helper to request the value when git connects to the
matching host. Wildcard bindings such as `@*.githubusercontent.com` cover
subdomains.

Combine a binding with a refreshable source:

```console
$ gantry start agent -image alpine:latest \
    -secret GITHUB_TOKEN@github.com=@/secure/token,ttl=60s
```

The broker answers only for the configured host and only when the network
policy permits that destination. Gantry warns at start if a binding is not
covered by the policy's domain allowlist. Deliveries, refusals, and resolution
failures appear by secret name in `gantry audit NAME`; values are omitted.

Bound secrets are also useful for remote MCP credentials. See
[MCP gateway](mcp-gateway.md#choose-remote-credentials).

## Secret lifecycle

For a named sandbox, `sandbox.json` stores secret names and source references,
not values. The behavior after a stop depends on the source:

- Environment values are gone. Export them again before `gantry resume`.
- File and command references remain in the saved configuration and resolve
  again on resume.
- Values loaded from a dotenv file or the dashboard are memory-only and must
  be supplied again.

```console
$ gantry stop agent
$ export GITHUB_TOKEN=...
$ gantry resume agent
```

Removing a secret from a running sandbox takes effect on the next use. A bound
credential requires no guest-side cleanup because its value was never sent to
the guest.

Registry credentials follow a separate path: the host image puller consumes
them and does not inject them into the VM. See
[Images](images.md#authenticate-to-registries).

## Complete browser OAuth

The OAuth callback bridge is enabled by default. When a supported Codex,
Claude, or Pi login prints a `127.0.0.1` or `localhost` callback URL, Gantry
opens the matching host-loopback callback temporarily so the host browser can
complete the guest login.

Disable the bridge when it is not needed:

```console
$ gantry start dev -image alpine:latest -oauth-bridge=false
```

The bridge accepts only supported callback paths and is not a general port
forward.

## Keep OAuth refresh tokens on the host

OAuth custody is available for Codex and Claude:

```console
$ gantry start agent -image ubuntu:latest -oauth-custody
$ gantry exec agent -- gantry-guest oauth login codex
```

Open the printed authorization URL in the host browser. The guest receives a
short-lived access token and a nonfunctional refresh-token sentinel. Gantry
keeps the real refresh token in the sandbox's protected host state, refreshes
it ahead of expiry, and pushes updated access tokens into the guest auth file.

Custody survives `gantry stop` and `gantry resume`. A fresh `gantry start` for
an existing name replaces that custody state, so log in again. If the provider
revokes the refresh token, the session fails closed and must be authenticated
again.

OAuth custody requires the callback bridge. Providers other than Codex and
Claude use the callback bridge without custody.

For diagrams of share, secret, OAuth, and MCP data flow, see
[Architecture](architecture.md#host-capability-bridges). For boundary details,
see [Security](security.md#credentials).
