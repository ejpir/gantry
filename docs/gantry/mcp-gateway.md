# MCP gateway

The MCP gateway lets sandbox tools use local and remote Model Context Protocol
servers. Gantry filters tools, injects remote credentials on the host side, and
audits calls without storing arguments, results, or secret values.

## Enable the gateway

Start with the built-in read-only filesystem server:

```console
$ gantry start dev -image alpine:latest -mcp
```

Point an agent at the guest proxy. For Claude Code:

```console
# claude mcp add gantry -- gantry-guest mcp-proxy
```

Gantry installs guest helpers in `/run/gantry/bin` and adds that directory to
`PATH` for new sessions.

## Limit filesystem access

The built-in server exposes `fs__read_file` and `fs__list_directory`. Restrict
it to a guest path and run it as an unprivileged user:

```console
$ gantry start dev -image alpine:latest \
    -mcp -mcp-fs-root /workspace -mcp-fs-user 1000:1000
```

`-mcp-fs-user` accepts an account name, numeric UID from the guest password
database, or `UID:GID`. Root is refused.

### Read a mounted workspace through MCP

The MCP root uses paths inside the guest. To expose a host project, align it
with a read-only share:

```console
$ gantry start dev -image alpine:latest \
    -share "code=$PWD,mount=/workspace,ro,uid=1000,gid=1000" \
    -mcp -mcp-fs-root /workspace -mcp-fs-user 1000:1000
```

A share without `mount=` appears at `/host/TAG`. The MCP user must have read
permission. Prefer a narrow root instead of `/`.

Remote MCP servers do not receive direct filesystem access, but an agent can
copy local tool results into a remote call. Keep remote allowlists narrow.

## Add a remote server

Use one repeatable `-mcp-remote` flag per streamable-HTTP server:

```console
$ export GITHUB_TOKEN=...
$ gantry start dev -image alpine:latest -mcp \
    -secret GITHUB_TOKEN@api.githubcopilot.com \
    -mcp-remote 'name=github,url=https://api.githubcopilot.com/mcp/,auth=bearer:GITHUB_TOKEN,allow=get_*,allow=list_*'
```

Fields:

| Field | Meaning |
|---|---|
| `name=ID` | Server ID; tools appear as `ID__tool`. |
| `url=URL` | Streamable-HTTP endpoint. |
| `auth=bearer:SECRET` | Bearer token from a named secret. |
| `auth=header:NAME:SECRET` | Custom credential header. |
| `auth=custody:PROVIDER` | Current access token from OAuth custody. |
| `allow=GLOB` | Expose matching tools; repeatable. Default: none. |
| `deny=GLOB` | Hide matching tools; repeatable and higher priority. |
| `redact=SECRET` | Mask another named secret in responses. |

URLs require HTTPS. Literal loopback HTTP is allowed only for local
development. Private, link-local, metadata, and other non-public destinations
are refused.

## Choose remote credentials

Bind normal secrets to the upstream host so they stay out of guest
environments:

```console
$ gantry start dev -image alpine:latest -mcp \
    -secret CORP_MCP_KEY@mcp.example.com=@/secure/mcp-token,ttl=60s \
    -mcp-remote 'name=corp,url=https://mcp.example.com/,auth=header:X-Api-Key:CORP_MCP_KEY,allow=search_*'
```

See [Host shares and secrets](shares-secrets.md#refreshable-secret-sources) for
source and rotation rules.

Use OAuth custody when the server accepts an OAuth access token:

```console
$ gantry start dev -image ubuntu:latest -mcp -oauth-custody \
    -oauth-provider ./company-oauth.json \
    -mcp-remote 'name=company,url=https://mcp.example.com/mcp,auth=custody:company-mcp,allow=read_*'
$ gantry exec dev -- gantry-guest oauth login company-mcp
```

See [OAuth](oauth.md#configure-a-public-oauth-client) for provider setup.

> [!WARNING]
> A configured upstream receives its credential. Redaction reduces accidental
> reflection but cannot stop a malicious server from transforming or encoding
> a secret. Use endpoint-bound, least-privilege credentials.

## Restrict tools

Remote servers expose no tools until an `allow=` pattern matches. `deny=` wins
over `allow=`. Gantry also blocks authorization and revocation-style tools.
Tool names and descriptions come from the server; connect only servers you
trust.

## Inspect servers and tools

Show saved configuration without resolving credentials:

```console
$ gantry mcp dev
```

Probe the effective tools of a running sandbox:

```console
$ gantry mcp tools dev
```

The live probe contacts upstreams and applies allow/deny rules.

## Manage servers in the dashboard

Open **MCP** (key `7`) to add, edit, or remove remote servers and configure the
filesystem server. The dashboard stores credential references, never values.
MCP capability tables are fixed for a worker lifetime, so changes to a running
sandbox take effect after restart.

## Inspect activity

```console
$ gantry audit dev
```

The audit records server/tool names, decisions, and sanitized failures—not
arguments, results, or credentials.

See [Architecture](architecture.md#mcp-and-credential-flow) for request and
credential flow, [Security](security.md#credentials) for cautions, and
[MCP confinement](mcp-worker-confinement.md) for worker boundaries.
