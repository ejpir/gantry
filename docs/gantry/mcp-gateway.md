# MCP gateway

The MCP gateway lets tools inside a sandbox use local and remote
[Model Context Protocol](https://modelcontextprotocol.io) servers. Gantry
applies a tool allowlist, injects remote credentials at the host-side
upstream, and records calls without recording arguments, results, or
credential values.

## Enable the gateway

Start a sandbox with the built-in read-only filesystem server:

```console
$ gantry start dev -image alpine:latest -mcp
```

Connect an agent to the in-guest proxy. For Claude Code, for example:

```console
# claude mcp add gantry -- gantry-guest mcp-proxy
```

Guest tools are installed in `/run/gantry/bin`, which Gantry adds to `PATH`
for new sessions. In an older sandbox, use the full command:

```console
# /run/gantry/bin/gantry-guest mcp-proxy
```

## Limit filesystem access

The built-in server exposes two tools:

- `fs__read_file`
- `fs__list_directory`

Set the directory visible to those tools with `-mcp-fs-root`:

```console
$ gantry start dev -image alpine:latest -mcp \
    -mcp-fs-root /workspace
```

The root is an absolute path inside the Linux guest. Reads outside it,
including symlink escapes, are refused.

The server runs as `nobody` by default. Select another unprivileged guest
identity with `-mcp-fs-user`:

```console
$ gantry start dev -image alpine:latest -mcp \
    -mcp-fs-root /workspace \
    -mcp-fs-user 1000:1000
```

The value can be a guest account name, a numeric UID found in the guest
password database, or an explicit `UID:GID`. Gantry refuses root.

## Add a remote server

Declare each streamable-HTTP server with a repeatable `-mcp-remote` flag:

```console
$ export GITHUB_TOKEN=...
$ gantry start dev -image alpine:latest -mcp \
    -secret GITHUB_TOKEN@api.githubcopilot.com \
    -mcp-remote 'name=github,url=https://api.githubcopilot.com/mcp/,auth=bearer:GITHUB_TOKEN,allow=*'
```

A remote specification is a comma-separated list of `k=v` fields:

| Field | Meaning |
| --- | --- |
| `name=ID` | Server ID. Its tools appear as `ID__tool`. Required. |
| `url=URL` | Streamable-HTTP endpoint. Required. |
| `auth=bearer:SECRET` | Send `Authorization: Bearer <SECRET>`. |
| `auth=header:NAME:SECRET` | Send a custom credential header. |
| `auth=custody:PROVIDER` | Use the live OAuth custody access token. |
| `allow=GLOB` | Expose matching tools. Repeatable; the default exposes none. |
| `deny=GLOB` | Hide matching tools even when allowed. Repeatable. |
| `redact=SECRET` | Remove another secret value from responses. Repeatable. |

Remote URLs must use HTTPS. Plain HTTP is accepted only for an explicit
loopback address, which is useful for local development. Gantry refuses
private, link-local, cloud-metadata, and other non-public destinations.
Invalid specifications fail before the sandbox starts.

## Choose remote credentials

Use a normal secret source for bearer or custom-header authentication:

```console
$ gantry start dev -image alpine:latest -mcp \
    -secret CORP_MCP_KEY@mcp.example.com=@/secure/mcp-token,ttl=60s \
    -mcp-remote 'name=corp,url=https://mcp.example.com/,auth=header:X-Api-Key:CORP_MCP_KEY,allow=search_*'
```

Binding the secret to the upstream host keeps it out of the guest environment.
The gateway resolves it on the host when starting an MCP session. Injected
credentials are automatically redacted from upstream results and errors.
See [Host shares and secrets](shares-secrets.md#refreshable-secret-sources) for
environment, file, and command sources.

Use a provider token held by OAuth custody when the remote accepts it:

```console
$ gantry start dev -image ubuntu:latest -mcp -oauth-custody \
    -mcp-remote 'name=ai,url=https://mcp.example.com/,auth=custody:claude,allow=read_*'
```

Log in with `gantry-guest oauth login claude` before using that remote. New
MCP sessions pick up refreshed access tokens automatically.

## Restrict tools

Remote servers expose no tools until an `allow=` pattern matches. Add narrow
patterns where possible:

```console
-mcp-remote 'name=github,url=https://example.com/mcp,auth=bearer:GITHUB_TOKEN,allow=get_*,allow=list_*,deny=delete_*'
```

`deny=` takes precedence over `allow=`. Gantry also refuses authorization and
revocation-style tools regardless of the configured patterns.

Tool names and descriptions are supplied by the remote server. Connect only
servers you trust, and treat `allow=*` as a deliberate grant.

## Inspect servers and tools

Show saved configuration without resolving or printing credential values:

```console
$ gantry mcp dev
SERVER  TYPE   DETAIL
fs      local  read-only filesystem: root /workspace, user 1000:1000, tools read_file,list_directory
github  remote https://api.githubcopilot.com/mcp/, auth bearer:GITHUB_TOKEN, allow=*
```

Probe the effective tool list of a running sandbox:

```console
$ gantry mcp tools dev
fs: list_directory, read_file
github: get_me, list_repos, search_code
```

The live probe contacts configured upstreams and applies `allow` and `deny`,
so it is useful for finding an unavailable server or an unexpected policy.

## Inspect activity

Read the host-side security audit trail:

```console
$ gantry audit dev
...
mcp: remote github configured (https://api.githubcopilot.com/mcp/, auth bearer (secret GITHUB_TOKEN))
mcp: call fs__read_file
mcp: denied call "fs__write_file" (policy)
mcp: call github__get_me
```

The audit records server and tool names, policy decisions, and sanitized
upstream failures. It does not record arguments, results, or credential
values.

For the host/guest request flow, credential injection, redaction, and resource
limits, see [Architecture](architecture.md#mcp-and-credential-flow). For the
trust boundary and operational cautions, see [Security](security.md#credentials).
The gateway runs in a per-sandbox confined worker. Its capability protocol,
platform enforcement, residual risks, and remaining guest-helper work are in
the [MCP worker confinement design](mcp-worker-confinement.md).
