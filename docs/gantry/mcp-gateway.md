# MCP gateway

The MCP gateway lets coding agents inside a sandbox use
[Model Context Protocol](https://modelcontextprotocol.io) servers without
holding their credentials. Agents point at an in-guest proxy endpoint; the
gateway runs on the host, multiplexes each session across local and remote
MCP servers, injects credentials into outbound requests, and redacts secret
values from everything that flows back.

Credentials are bound to the configured upstream origin: the guest — and any
process inside it — never sees an API token, only the gateway does.

## Enable the gateway

```console
$ gantry start dev -image alpine:latest -mcp
```

This starts the gateway with its built-in, read-only filesystem server. The
agent inside the sandbox connects over the guest proxy:

```console
# gantry-guest mcp-proxy
```

For Claude Code, for example:

```console
# claude mcp add gantry -- gantry-guest mcp-proxy
```

The filesystem server serves tools `fs__read_file` and `fs__list_directory`,
contained to `-mcp-fs-root` (default `/`) by a path-validating jail, running
as `-mcp-fs-user` (default `nobody`; `root` is refused). Paths are absolute
in the guest and must stay inside the server root.

## Add a remote server

Remote servers speak the MCP streamable-HTTP transport and are declared at
start time with `-mcp-remote` (repeatable):

```console
$ gantry start dev -image alpine:latest -mcp \
    -secret GITHUB_TOKEN \
    -mcp-remote 'name=github,url=https://api.githubcopilot.com/mcp/,auth=bearer:GITHUB_TOKEN,allow=*'
```

A spec is comma-separated `k=v` pairs:

| Field | Meaning |
| --- | --- |
| `name=ID` | Server id; its tools appear as `ID__tool`. Required. |
| `url=URL` | `https://` endpoint. `http://` is accepted only for loopback literals. Required. |
| `auth=bearer:SECRET` | Send `Authorization: Bearer <value of SECRET>`. |
| `auth=header:NAME:SECRET` | Send header `NAME: <value of SECRET>`. |
| `auth=custody:PROVIDER` | Send the live custody access token for PROVIDER (requires `-oauth-custody`); refreshed tokens reach new sessions automatically. |
| `allow=GLOB` | Expose only matching tools; repeatable. Default: expose none. |
| `deny=GLOB` | Hide matching tools even if allowed; repeatable. |
| `redact=SECRET` | Scrub the value of SECRET from this server's responses; repeatable. |

Secrets resolve through the normal [secret sources](shares-secrets.md#refreshable-secret-sources)
(environment, `@/path`, `!cmd`) on the host. Injected values are
automatically added to the server's redaction set.

## Security properties

- **Custody:** credential values live in the gateway process on the host.
  Guests receive tool results, never headers.
- **Origin binding:** redirects on a credentialed upstream are refused, so a
  credential cannot be steered to a different origin.
- **SSRF guard:** the gateway resolves and validates the target inside the
  dial itself and connects to the validated address. Loopback, private,
  link-local (including the cloud metadata address), and CGNAT targets are
  refused; a bad `url=` fails `gantry start` immediately.
- **Default deny:** a tool that matches neither `allow` nor any configured
  server gets the same refusal as a nonexistent tool — the guest cannot
  enumerate what is configured but hidden.
- **Redaction:** configured secret values, plus every injected credential,
  are replaced with `[REDACTED-BY-GANTRY-MCP-GATEWAY]` in tool results and
  in upstream error text before either reaches the guest or the audit log.
- **Audit:** sessions, calls, denies, and upstream errors are recorded
  host-side (`gantry audit NAME`) without credential values.
- **Bounded:** frames and responses are capped at 1 MiB; a session has at
  most 16 in-flight requests.

Tool descriptions from a remote upstream are trusted content — connect only
upstreams you trust. Per-tool `allow`/`deny` limits what a misbehaving
server can offer.

## Inspect activity

Every session, call, policy denial, and upstream error is recorded in the
sandbox's host-side audit log — with tool names and server ids, never
credential values:

```console
$ gantry audit dev
...
mcp: remote github configured (https://api.githubcopilot.com/mcp/, auth bearer (secret GITHUB_TOKEN))
mcp: call fs__read_file
mcp: denied call fs__write_file (policy)
mcp: call github__get_me
```
