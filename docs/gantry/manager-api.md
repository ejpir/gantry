# Manager API

The Gantry manager exposes sandbox lifecycle and bounded command execution
over HTTP/1.1 on a Unix-domain socket or bearer-authenticated HTTPS.

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

## Serve over TLS

For remote clients, the same API can be served over TLS with mandatory
bearer-token authentication:

```console
$ gantry serve --mint-token          # print a fresh token for the token file
$ gantry serve -listen tls://0.0.0.0:8443 \
    --self-signed --token-file ~/.gantry/manager-tokens
```

Every request on a TLS listener requires `Authorization: Bearer TOKEN`;
plaintext network listeners are refused outright. `--self-signed` material
lives under `~/.gantry/serve/` and its fingerprint, printed at startup as
`tls fingerprint sha256:…`, is what remote clients pin. Org PKI can be
supplied with `--tls-cert`/`--tls-key` instead. The token file is reloaded
when it changes, so rotation is a file edit. A bearer token is equivalent to
host-shell authority on the serving machine — store it `0600` and treat it
accordingly. Clients configure a profile with `gantry remote add` and run
the everyday verbs with `-remote NAME` (see
[CLI reference](cli-reference.md#remote-managers)). The
[Remote access guide](remote-access.md) covers standalone profiles, TUI creation,
SSH, and optional organization discovery. Organization login is not required
for standalone managers and does not replace their bearer authentication.

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
registry transfer. Warm the image cache with the CLI or `POST /v1/images/pull`
first (the TUI remote create flow does this for missing images):

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
      "shares": ["workspace=/absolute/project/path,mount=/workspace,ro"],
      "networkPolicy": "/absolute/policy.json"
    }' \
    http://gantry.local/v1/sandboxes
```

Lifecycle mutations return an operation object. Supply an `Idempotency-Key`
when a caller may retry after losing a response. Reusing a key with the same
request returns the existing operation; reusing it for a different request is
rejected.

`organizationPolicy` optionally supplies the canonical signed snapshot
(`bundle` as base64, `public_key` PEM, `profile`). It is reverified by the launch
resolver before boot, not trusted as proof of a remote user's organization
identity. It cannot be combined with OAuth custody.

## Configure an existing sandbox

`PATCH /v1/sandboxes/{name}` accepts only explicitly supplied mutable settings:
`ssh`, `devContainers`, `memoryMiB`, `cpus`, and `processIsolation`. For example:

```json
{"ssh": false, "memoryMiB": 1024}
```

Unspecified settings are preserved. Supply `Idempotency-Key` to replay rather
than reapply an update. The response is an operation with
`configure: {"restartRequired": true|false}`. Live updates go through the daemon;
stopped updates retain the launch lock and existing validation/transactions.
Invalid/empty updates return 400, missing sandboxes 404, and launch/configuration
conflicts 409. Configuration is never a replacement upload of `sandbox.json`.

## Run a low-level VM

`POST /v1/run` accepts the canonical `RunVMRequest`: explicit manager-host
`kernel` and `initrd`/`rootfs`, optional disks/shares/network/vsock settings,
resources, bounded `stdin`, `timeoutSeconds` and `maxOutputBytes`. It invokes the
existing raw launcher in a child process, not a shell or arbitrary caller argv.
This is deliberately not named-sandbox creation.

The synchronous operation response includes `run` with `exitCode`, `output`
and `truncated`; nonzero helper exits still complete the operation. Deadline
exit is 124 and cancellation is 130. Console capture defaults to 16 KiB (64 KiB
maximum); runtime defaults to 300 seconds (3600 maximum). The submission's
context or manager shutdown cancels and reaps the child. Raw launches use a
separate serialization lock and bounded lifecycle admission. Matching concurrent
idempotent retries return 202; completed retries return the same stored result.

## Images, SSH and policy

Additional routes use the same authentication and canonical OpenAPI types:

- `GET /v1/images`, `POST /v1/images/pull`, `POST /v1/images/delete`.
  Pulls return an asynchronous operation; poll `GET /v1/operations/{id}`.
  Registry helpers run in a short-lived process on the manager host. Pulls
  survive client disconnection but operation records do not survive restart.
- `GET /v1/ssh/hostkey` returns the public install key. Bodyless
  `POST /v1/sandboxes/{name}/ssh`, with `Connection: Upgrade` and
  `Upgrade: gantry-ssh`, upgrades to a bounded SSH tunnel to the existing
  gateway. No arbitrary destination/socket is accepted.
- `GET/PUT /v1/sandboxes/{name}/net-policy` uploads public network policy data
  and delegates to existing local enforcement.
- `GET/PUT /v1/sandboxes/{name}/policy` inspects or changes signed organization
  snapshots; changing/clearing requires a stopped sandbox and the launch lock.
- `GET /v1/sandboxes/{name}/audit` returns a bounded audit tail, not a full
  persisted sandbox configuration.

See the [OpenAPI contract](../../api/managerapi/openapi.yaml) for request shapes
and the [remote CLI examples](remote-access.md#cli-operations).

## List and inspect sandboxes

```console
$ curl --unix-socket "$HOME/.gantry/manager.sock" \
    http://gantry.local/v1/sandboxes

$ curl --unix-socket "$HOME/.gantry/manager.sock" \
    http://gantry.local/v1/sandboxes/api-dev
```

## Stop, start, and delete

Sandbox inspection reports `starting` until both guest RPC and the local
control broker are ready, then `running`. A stopped daemon reports `stopped`.
The CLI and dashboard use the same readiness definition.

The `desired` object describes saved boot settings; `active` describes the
current VM allocation. Changing memory, CPUs, process isolation, or the
Dev Containers topology sets `restartRequired` until the next start.
Existing top-level `cpus` and `memoryMiB` fields retain their saved-setting
meaning. `active` is absent for stopped sandboxes and older daemons that
have not published a boot snapshot.

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
