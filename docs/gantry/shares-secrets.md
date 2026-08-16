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

## Secret lifecycle

For persistent sandboxes, `sandbox.json` stores only configured secret names.
Values travel from the launcher to the sandbox daemon through a bounded stdin
handshake, remain in daemon memory for that VM lifetime, and enter only the
guest process environment. Gantry scrubs those keys from the host daemon's
environment.

After `gantry stop`, values are gone. Before `gantry resume`, export every
configured name again:

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

