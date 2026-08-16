# Manager API

The Gantry manager exposes local sandbox lifecycle and bounded command
execution over HTTP/1.1 on a Unix-domain socket.

Use the API when a local agent harness or development tool needs structured
results instead of terminal-oriented CLI output.

## Start the manager

```console
$ gantry serve
```

The default socket is `~/.gantry/manager.sock`. Choose another path with:

```console
$ gantry serve -socket /run/user/1000/gantry-manager.sock
```

The production listener restricts the socket and verifies same-user local
connections. It is not a TCP authentication protocol and must not be exposed
through a network proxy or shared with untrusted users.

## Check health

Use `curl` with Unix-socket transport:

```console
$ curl --unix-socket "$HOME/.gantry/manager.sock" \
    http://gantry.local/v1/health
```

Fetch the exact API contract served by the installed build:

```console
$ curl --unix-socket "$HOME/.gantry/manager.sock" \
    http://gantry.local/v1/openapi.yaml
```

The repository also contains the
[OpenAPI 3.1 contract](../../api/managerapi/openapi.yaml).

## Create a sandbox

The manager create path is cache-only, so an API request does not trigger a
registry transfer. Warm the image cache with the CLI first:

```console
$ gantry image pull alpine:latest
```

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
      "shares": ["workspace=/absolute/project/path@/workspace,ro"],
      "networkPolicy": "/absolute/policy.json"
    }' \
    http://gantry.local/v1/sandboxes
```

Lifecycle mutations return an operation object. Supply an `Idempotency-Key`
when a caller may retry after losing a response. Reusing a key with the same
request returns the existing operation; reusing it for a different request is
rejected.

## List and inspect sandboxes

```console
$ curl --unix-socket "$HOME/.gantry/manager.sock" \
    http://gantry.local/v1/sandboxes

$ curl --unix-socket "$HOME/.gantry/manager.sock" \
    http://gantry.local/v1/sandboxes/api-dev
```

## Stop, start, and delete

```console
$ curl --unix-socket "$HOME/.gantry/manager.sock" -X POST \
    http://gantry.local/v1/sandboxes/api-dev/stop

$ curl --unix-socket "$HOME/.gantry/manager.sock" -X POST \
    http://gantry.local/v1/sandboxes/api-dev/start

$ curl --unix-socket "$HOME/.gantry/manager.sock" -X DELETE \
    http://gantry.local/v1/sandboxes/api-dev
```

## Execute a command

The exec endpoint captures combined output with explicit time and size bounds:

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

A non-zero guest exit is still an HTTP `200` result with `exitCode`, `output`,
and `truncated` fields. Infrastructure timeouts and invalid or oversized
requests use HTTP error responses.

## Pass secrets by name

The API never accepts secret values. Start the manager with values in its own
environment, then put only the names in `secretNames`:

```console
$ export GITHUB_TOKEN=...
$ gantry serve
```

```json
{
  "name": "agent",
  "image": "alpine:latest",
  "secretNames": ["GITHUB_TOKEN"]
}
```

The same [secret lifecycle](shares-secrets.md#secret-lifecycle) applies as it
does to the CLI.

## Watch lifecycle events

Subscribe to the bounded server-sent event stream:

```console
$ curl -N --unix-socket "$HOME/.gantry/manager.sock" \
    http://gantry.local/v1/events
```

Events report current operation transitions. The stream does not replay
historical events; use `/v1/operations/{id}` to inspect a known operation.
