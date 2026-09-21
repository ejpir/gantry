# Manager API

The manager exposes sandbox lifecycle and bounded command execution over
HTTP/1.1. Use it when an agent or development tool needs structured results.
The installed server exposes the exact [OpenAPI contract](../../api/managerapi/openapi.yaml).

## Start a local manager

```console
$ gantry serve
```

The default endpoint is `~/.gantry/manager.sock`. Choose another Unix socket
with `-socket`.

```console
$ curl --unix-socket "$HOME/.gantry/manager.sock" \
    http://gantry.local/v1/health
$ curl --unix-socket "$HOME/.gantry/manager.sock" \
    http://gantry.local/v1/openapi.yaml
```

The socket is private and same-user authenticated. Do not expose it through a
network proxy or share it with untrusted users.

## Start the local manager on demand

On Linux and macOS, a desktop or other same-user client can ask Gantry to start
or reuse the default local manager:

```console
$ gantry serve --ensure
{"socket":"/home/user/.gantry/manager.sock","version":"v1","started":true,"pid":12345}
```

The response is JSON; `pid` is present only when this invocation starts a
process. The command checks readiness before returning and is bounded to eight
seconds. Concurrent launchers share a startup lock, and the ordinary
manager-state lock remains the single-instance authority. The detached child
serves the **same `/v1` HTTP API** over the private Unix socket, never a TCP
listener. Its output goes to the private `manager.log` beside the socket.
Closing the requesting application does not stop this manager or its sandboxes.

Only a missing or refused default endpoint permits startup. Incompatible or
unhealthy servers, permission errors, symlinks, and non-socket paths are not
replaced. A `-socket` argument to `--ensure` can confirm the default path but
cannot retarget startup. `GANTRY_MANAGER_SOCKET` overrides are connect-only.
TLS, token, listener, and policy-feed flags cannot accompany `--ensure`.

An existing manager holding the state lock is never displaced, including a
TLS-only manager. Saved organization policy-feed state also blocks automatic
startup: restart that manager explicitly with its correct `-policy-feed`
configuration. The desktop uses this command only for its default local
connection; remote failures never cause local startup.

The sandbox-specific `ctl.sock` remains an internal broker protocol. Clients
should use the manager API, not substitute that socket for `manager.sock`.

## Serve over TLS

Remote listeners require TLS and a bearer token:

```console
$ gantry serve --mint-token > ~/.gantry/manager.token
$ chmod 600 ~/.gantry/manager.token
$ gantry serve -listen tls://0.0.0.0:8443 \
    --self-signed --token-file ~/.gantry/manager.token
```

Every request needs `Authorization: Bearer TOKEN`. Plaintext network listeners
are refused. Use `--tls-cert` and `--tls-key` for your own PKI. The token file
is reloaded when replaced.

A token grants host-shell authority. Keep the listener on a trusted network and
treat the token like a private key. See [Remote access](remote-access.md) for
client profiles and TLS trust.

## Create a sandbox

The API is cache-only: pull the image on the manager first, or call
`POST /v1/images/pull`.

```console
$ curl --unix-socket "$HOME/.gantry/manager.sock" \
    -H 'Content-Type: application/json' \
    -H 'Idempotency-Key: create-api-dev-1' \
    -d '{
      "name": "api-dev",
      "image": "alpine:latest",
      "rw": true,
      "memoryMiB": 1024,
      "cpus": 2,
      "shares": ["workspace=/absolute/project,mount=/workspace,ro"]
    }' \
    http://gantry.local/v1/sandboxes
```

Lifecycle mutations return an operation. Use an `Idempotency-Key` when a caller
may retry: the same key and request replay the operation; different content is
rejected.

`organizationPolicy` may contain a signed snapshot (`bundle`, `public_key`, and
`profile`). Gantry verifies it before boot. It cannot be combined with OAuth
custody.

## Inspect and control sandboxes

```console
$ curl --unix-socket "$HOME/.gantry/manager.sock" \
    http://gantry.local/v1/sandboxes
$ curl --unix-socket "$HOME/.gantry/manager.sock" \
    http://gantry.local/v1/sandboxes/api-dev
$ curl --unix-socket "$HOME/.gantry/manager.sock" -X POST \
    http://gantry.local/v1/sandboxes/api-dev/stop
$ curl --unix-socket "$HOME/.gantry/manager.sock" -X POST \
    http://gantry.local/v1/sandboxes/api-dev/start
$ curl --unix-socket "$HOME/.gantry/manager.sock" -X DELETE \
    http://gantry.local/v1/sandboxes/api-dev
```

Inspection reports `starting`, `running`, or `stopped`. `desired` contains
saved next-boot settings; `active` contains current VM resources.
`restartRequired` shows when they differ.

`PATCH /v1/sandboxes/{name}` updates only supplied `ssh`, `devContainers`,
`memoryMiB`, `cpus`, or `processIsolation` fields. It never replaces
`sandbox.json`.

## Execute a command

```console
$ curl --unix-socket "$HOME/.gantry/manager.sock" \
    -H 'Content-Type: application/json' \
    -d '{
      "argv": ["sh", "-lc", "pwd && uname -a"],
      "cwd": "/workspace",
      "timeoutSeconds": 30,
      "maxOutputBytes": 1048576
    }' \
    http://gantry.local/v1/sandboxes/api-dev/exec
```

A guest nonzero exit is an HTTP `200` response with `exitCode`, `output`, and
`truncated`. Invalid requests and infrastructure failures use HTTP errors.

## Other routes

The OpenAPI contract defines all request and response shapes. Main route groups
are:

- `/v1/images`, `/v1/images/pull`, and `/v1/images/delete` for image operations;
- `/v1/sandboxes/{name}/ssh` for an authenticated SSH upgrade;
- `/v1/sandboxes/{name}/net-policy` for network policy;
- `/v1/sandboxes/{name}/policy` for live organization policy and controlled
  restart rollout;
- `/v1/sandboxes/{name}/audit` for a bounded audit tail;
- `/v1/dashboard` for the complete non-secret dashboard snapshot and host
  limits;
- `/v1/dashboard/actions` for the dashboard's validated configuration actions;
- `/v1/dashboard/packets/{name}` for bounded in-memory packet capture;
- `/v1/run` for a bounded low-level VM run; and
- `/v1/operations/{id}` for operation state.

Organization-policy mutation applies live to a running sandbox by default. Add
`"restart": true` to explicitly request controlled stop/update/resume. A
stopped sandbox remains stopped. The signed snapshot is always verified on the
manager. After an organization-wide feed generation is active, per-sandbox
replacement and clearing are refused; new manager-created sandboxes inherit the
feed snapshot.

Low-level run accepts manager-host asset paths and bounded input, output, and
timeouts. It is not named-sandbox creation and is disabled while an
organization-wide feed policy is active. See
[Architecture](architecture.md#remote-manager-transport) for execution and SSH
tunnel boundaries.

## Secret handling

Sandbox creation never accepts secret values. Start the manager with values in
its own environment and send only names:

```console
$ export GITHUB_TOKEN=...
$ gantry serve
```

```json
{"name": "agent", "image": "alpine:latest", "secretNames": ["GITHUB_TOKEN"]}
```

The normal [secret lifecycle](shares-secrets.md#secret-lifecycle) applies.

The authenticated dashboard action endpoint additionally supports the same
live, memory-only secret operation as the local TUI. That write-only value is
sent only over the verified manager transport, is never returned in a snapshot
or response, and is not persisted. Registry credentials use the same
write-only rule and remain manager-host credentials; they never enter a
sandbox.

## Watch events

```console
$ curl -N --unix-socket "$HOME/.gantry/manager.sock" \
    http://gantry.local/v1/events
```

The server-sent stream reports current operation transitions but does not
replay history. Query a known operation ID for its retained result.
