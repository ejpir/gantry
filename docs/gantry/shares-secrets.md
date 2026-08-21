# Host shares and secrets

Host shares expose selected directories through virtio-fs. Secrets add
environment values to guest processes without putting those values in command
arguments or persistent sandbox configuration.

## Share a host directory

Share a project at its default container path, `/host/code`:

```console
$ gantry start dev -image alpine:latest \
    -share "code=$PWD"
```

Choose an explicit container path after `@`:

```console
$ gantry start dev -image alpine:latest \
    -share "code=$PWD@/workspace"
```

The full format is:

```text
TAG=HOST_PATH[@CONTAINER_PATH][,ro][,uid=N,gid=N]
```

Tags identify shares in the live control plane. Container paths after `@`
must be absolute.

## Make a share read-only

Append `,ro`:

```console
$ gantry start review -image alpine:latest \
    -share "source=$PWD@/workspace,ro"
```

Read-only behavior is enforced by the host filesystem backend, not only by a
guest mount flag.

> [!WARNING]
> A read-write share grants the guest the launching user's access to that
> directory. It is an intentional path through the VM boundary. Share the
> smallest directory the workload needs.

## Map guest-visible ownership

Use `uid` and `gid` together to replace the numeric owner shown inside the
guest without changing ownership on the host:

```console
$ gantry start dev -image node:latest \
    -share "code=$PWD@/workspace,uid=1000,gid=1000"
```

Both options are required when either is present.

## Add and remove shares live

Add a share to a running sandbox:

```console
$ gantry share add dev "docs=$PWD/docs@/reference,ro"
$ gantry share ls dev
```

Replace an existing tag:

```console
$ gantry share add --replace dev "docs=$PWD/new-docs@/reference,ro"
```

Remove it:

```console
$ gantry share remove dev docs
```

By default, live changes update `sandbox.json` and return after the share is
visible or removed. Use `--ephemeral` to affect only the current boot. A
normal remove waits for active handles to drain; `--force` revokes the export
when a workload will not release them.

On Linux and macOS, host filesystem notifications keep guest directory and
attribute caches coherent. The Windows backend uses conservative cache
behavior and supports local NTFS directories; UNC, network, removable, and
non-NTFS roots are not supported.

## Inject secrets

Export a value on the host, then name it on the Gantry command line:

```console
$ export GITHUB_TOKEN=...
$ gantry start agent -image alpine:latest -secret GITHUB_TOKEN
$ gantry exec agent -- sh -lc 'test -n "$GITHUB_TOKEN"'
```

Read a value from a file instead:

```console
$ gantry start agent -image alpine:latest \
    -secret GITHUB_TOKEN=@/secure/token
```

Or load a dotenv-style file:

```console
$ gantry start agent -image alpine:latest \
    -secret-file /secure/agent.env
```

Repeat `-secret` and `-secret-file` as needed. Later definitions of the same
name win.

Gantry refuses `-secret NAME=literal`. Literal values in argv can be exposed
by process inspection and shell history.

## Refreshable secret sources

File- and command-backed secrets are not copied at start. The sandbox daemon
re-resolves them when they are used, so rotating the source is picked up by a
running sandbox without a restart:

```console
$ gantry start agent -image alpine:latest \
    -secret GITHUB_TOKEN=@/secure/token,ttl=60s
```

```console
$ gantry start agent -image alpine:latest \
    -secret GITHUB_TOKEN='!gh auth token'
```

The `,ttl=` suffix sets how long a resolved value is cached (default: 60s for
files, 5m for commands; `ttl=0` re-resolves on every use). A command source
runs an argv on the host — never a shell string — and captures stdout. This
covers `op read ...`, `pass ...`, and similar tools without per-vendor support.

If a previously working source stops resolving (the file was deleted, the
command fails), Gantry fails closed: the cached value is dropped and nothing
stale is served. The daemon log names the failing source, never its value.

Environment-sourced secrets (`-secret NAME`) are still read once at start:
environment variables do not change for a running process, so there is nothing
to refresh.

## Bind a secret to a host

Appending `@host` to the name binds the secret to that host and changes how it
is delivered:

```console
$ export GITHUB_TOKEN=...
$ gantry start agent -image alpine:latest -secret GITHUB_TOKEN@github.com
```

A bound secret is never placed in the guest environment or written to guest
disk. Instead, Gantry stages a git credential helper inside the guest and
points git at it; when git needs credentials for the bound host, the helper
asks the sandbox daemon over the VM's vsock channel, and the daemon answers
from memory. Wildcard bindings (`@*.githubusercontent.com`) cover subdomains.

The daemon answers only for the bound host, and only when the sandbox's
network policy allows egress to that host. Every delivery, refusal, and source
failure is logged by name in `daemon.log` and readable from a running sandbox
with `gantry audit NAME` — values are structurally unloggable. Removing the
secret on a running sandbox (the dashboard's secret controls) takes effect on
the next git operation, with nothing to scrub guest-side.

At start time gantry warns when a bound secret's `@host` is not covered by the
`-net-policy` domain allowlist — the broker would hold the value but refuse
every guest request for it, an expensive no-op best caught before boot.

Bound secrets combine with refreshable sources —
`-secret GITHUB_TOKEN@github.com=@/secure/token,ttl=60s` — so a rotated token
file reaches in-flight sessions.

## Secret lifecycle

For persistent sandboxes, `sandbox.json` stores only configured secret names.
Values travel from the launcher to the sandbox daemon through a bounded stdin
handshake, remain in daemon memory for that VM lifetime, and enter only the
guest process environment. Gantry scrubs those keys from the host daemon's
environment.

After `gantry stop`, values are gone. Before `gantry resume`, export every
configured environment-sourced name again (file- and command-backed sources
re-resolve from their references and need no re-export):

```console
$ export GITHUB_TOKEN=...
$ gantry resume agent
```

The dashboard can load or remove a memory-only secret on a running sandbox.
It lists names and state, never values.

Registry credentials are separate: the host image puller consumes them and
does not send them into the VM. See [Images](images.md#authenticate-to-registries).

> [!IMPORTANT]
> A process inside the sandbox can read secrets injected into its environment.
> Pair secrets with a default-deny [network policy](networking.md#define-an-egress-policy)
> that allows only the services that should receive them.

## OAuth callback bridge

CLI-based agents often start a browser login on a guest loopback URL. Gantry
enables a bounded OAuth bridge by default for supported Codex, Claude, and Pi
callback patterns.

When the agent prints a supported `127.0.0.1` or `localhost` callback URL,
Gantry opens the corresponding host loopback listener for a limited time. The
browser reaches the host listener, and Gantry replays the callback into the
guest loopback service. The listener accepts only the expected callback shape
and is not a general port forward.

Disable it for a sandbox that does not need browser OAuth:

```console
$ gantry start dev -image alpine:latest -oauth-bridge=false
```

## OAuth custody

For Codex and Claude, Gantry can additionally hold the OAuth refresh token on
the host and keep the guest on short-lived access tokens:

```console
$ gantry start agent -image ubuntu:latest -oauth-custody
$ gantry exec agent -- gantry-guest oauth login codex
```

`gantry-guest oauth login` prints an authorize URL; open it in your host
browser. (Guest tools install into `/run/gantry/bin`, which is on the PATH of
sessions and execs once installed; use the full path in older sandboxes.)
The daemon completes the exchange itself: the refresh token is stored
host-side (a `0600` file in the sandbox state directory, so `gantry stop` and
`gantry resume` keep the session), and the guest's auth file receives the
current access token plus a sentinel refresh token. The daemon refreshes ahead
of expiry and pushes the fresh access token into the guest automatically.

A process exfiltrating the guest auth file gets an access token that stops
working at expiry and a refresh token that never works.

Custody state lives in the sandbox state directory. `gantry resume` preserves
it (the refresh loop picks the session back up); `gantry start` on an existing
name replaces the sandbox and its custody state with it — log in again after a
fresh start.

Custody is provider-specific and supports Codex and Claude only; other
providers use the transparent callback bridge above. If the provider revokes
the refresh token, Gantry drops the session and the agent fails loudly — log
in again with the same command. Custody requires the callback bridge; it is
off by default and the transparent bridge alone remains the standard behavior.

