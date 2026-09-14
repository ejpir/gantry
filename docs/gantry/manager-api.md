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
- `/v1/sandboxes/{name}/policy` for organization policy;
- `/v1/sandboxes/{name}/audit` for a bounded audit tail;
- `/v1/run` for a bounded low-level VM run; and
- `/v1/operations/{id}` for operation state.

Low-level run accepts manager-host asset paths and bounded input, output, and
timeouts. It is not named-sandbox creation. See
[Architecture](architecture.md#remote-manager-transport) for execution and SSH
tunnel boundaries.

## Pass secrets by name

The API never accepts secret values. Start the manager with values in its own
environment and send only names:

```console
$ export GITHUB_TOKEN=...
$ gantry serve
```

```json
{"name": "agent", "image": "alpine:latest", "secretNames": ["GITHUB_TOKEN"]}
```

The normal [secret lifecycle](shares-secrets.md#secret-lifecycle) applies.

## Watch events

```console
$ curl -N --unix-socket "$HOME/.gantry/manager.sock" \
    http://gantry.local/v1/events
```

The server-sent stream reports current operation transitions but does not
replay history. Query a known operation ID for its retained result.
