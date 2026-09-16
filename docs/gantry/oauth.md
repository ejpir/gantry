# OAuth

Gantry supports two host-side OAuth features:

- the **callback bridge** lets unmodified guest CLIs finish browser login; and
- **OAuth custody** keeps refresh tokens on the host and delivers only the
  access needed by supported tools.

These features are separate from [organization login](organization-login.md),
which authenticates the host user for organization policy and remote discovery.

## Complete browser login

The callback bridge is enabled by default. Gantry watches for new guest
loopback listeners on ports `1455`, `53692`, and `32768–65535`, opens a
temporary host-loopback gate, and forwards OAuth results to the guest.

This works for unmodified CLIs, including tools started by agents or terminal
multiplexers. It is not a general port forward: requests must contain a
non-empty `state` and either `code` or `error`. GET callbacks and URL-encoded
`response_mode=form_post` callbacks are supported.

Disable it when browser login is unnecessary:

```console
$ gantry start dev -image alpine:latest -oauth-bridge=false
```

The guest CLI still validates state and PKCE. Browser headers, cookies, and
guest-generated response pages are not exposed by the host bridge.

## Keep refresh tokens on the host

Enable custody, then start a supported login inside the sandbox:

```console
$ gantry start agent -image ubuntu:latest -oauth-custody
$ gantry exec agent -- gantry-guest oauth login codex
```

Built-in provider names are `codex`, `claude`, and `github`. For Codex and
Claude, Gantry writes the current access token and a nonfunctional refresh-token
sentinel into the expected guest auth file. The real refresh token remains in
the sandbox's protected host state and is used for refresh.

For GitHub:

```console
$ gantry exec agent -- gantry-guest oauth login github
```

Gantry uses GitHub's device flow. Git-over-HTTPS receives the token on demand
through the credential broker for `github.com`; no `GITHUB_TOKEN` environment
variable or `gh` auth file is created.

Custody survives stop and resume. Starting an existing name afresh replaces
custody state. Revoked or failed refreshes fail closed and require a new login.
Organization-governed sandboxes do not currently support custody.

## Configure a public OAuth client

Use `-oauth-provider` for another public client, including an MCP server:

```json
{
  "name": "company-mcp",
  "authorize_url": "https://auth.example.com/authorize",
  "token_url": "https://auth.example.com/token",
  "client_id": "YOUR_PUBLIC_CLIENT_ID",
  "redirect_uri": "http://127.0.0.1:53693/callback",
  "scope": "mcp offline_access",
  "resource": "https://mcp.example.com/mcp"
}
```

Register the callback URI with the provider, then run:

```console
$ gantry start dev -image ubuntu:latest -oauth-custody \
    -oauth-provider ./company-oauth.json \
    -mcp-remote 'name=company,url=https://mcp.example.com/mcp,auth=custody:company-mcp,allow=read_*'
$ gantry exec dev -- gantry-guest oauth login company-mcp
```

Provider fields:

| Field | Meaning |
|---|---|
| `name` | Unique lowercase provider name. |
| `grant` | `authorization_code` (default) or `device_code`. |
| `authorize_url` | Authorization endpoint for code flow. |
| `device_authorization_url` | Device endpoint for device flow. |
| `token_url`, `client_id` | Token endpoint and public client ID. |
| `redirect_uri` | IPv4 loopback callback; port `0` chooses a dynamic port. |
| `scope` | Space-separated scopes. |
| `resource` | Optional RFC 8707 resource. |
| `exchange_encoding`, `refresh_encoding` | `form` (default) or `json`. |
| `credential_hosts` | Exact hosts allowed to request the access token through the guest git helper. |

Authorization and token endpoints require HTTPS; literal `127.0.0.1` HTTP is
allowed for local development. Provider files are copied into sandbox
configuration. Changing endpoints, client, scope, or resource invalidates the
saved session.

Only public clients are supported. Do not put client secrets in provider JSON.
Automatic authorization-server discovery and dynamic client registration are
not implemented.

## Security notes

- Custody keeps refresh tokens out of the guest, but a delivered access token
  still has its normal authority.
- Give an MCP token only to the configured server you trust with it.
- Callback bridging requires the trusted `gantry-guest` helper.
- Already delivered tokens cannot be recalled.

See [Architecture](architecture.md#oauth-bridge-and-custody) for protocol,
storage, and delivery details, and [Security](security.md#credentials) for the
trust boundary.
