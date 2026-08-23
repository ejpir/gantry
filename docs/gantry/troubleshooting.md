# Troubleshoot Gantry

Start with the command's error output and the sandbox logs. Gantry keeps the
current and previous daemon diagnostics so failed starts remain inspectable.

## Find sandbox logs

For a sandbox named `dev`, inspect:

```console
$ ls -la "$HOME/.gantry/sandboxes/dev"
$ tail -n 200 "$HOME/.gantry/sandboxes/dev/daemon.log"
$ tail -n 200 "$HOME/.gantry/sandboxes/dev/console.log"
$ tail -n 200 "$HOME/.gantry/sandboxes/dev/worker-vmm.log"
$ tail -n 200 "$HOME/.gantry/sandboxes/dev/worker-net.log"
```

`daemon.log.previous` contains the preceding boot when available.
`isolation.json` records the effective topology and verified confinement
properties.

If `GANTRY_HOME` is set, it is the sandbox root itself; use
`$GANTRY_HOME/dev` instead.

## The hypervisor is unavailable

### Linux

Confirm that KVM exists and the current user can open it:

```console
$ ls -l /dev/kvm
$ test -r /dev/kvm -a -w /dev/kvm && echo OK
```

Enable hardware virtualization in firmware if necessary. Inside a VM or
hosted runner, enable nested virtualization. Group membership changes usually
require a new login session.

### macOS

Gantry supports Apple silicon and requires the Hypervisor.framework
entitlement present in release builds. An unsigned or locally rebuilt binary
may need to be signed with the repository entitlement file.

### Windows

Enable Windows Hypervisor Platform and verify that the host or outer VM
exposes hardware virtualization. Windows support is experimental; collect
`daemon.log`, `console.log`, and `worker-vmm.log` with any report.

## Guest assets cannot be downloaded

The first start downloads the matching kernel, system root, and default image.
Gantry refuses an asset when its SHA-256 sidecar is missing, malformed, or does
not match.

Check access to GitHub Releases, then retry. Release tags should be immutable.
For an intentionally rebuilt tag, run `gantry update --force`; build-scoped
asset paths then download a matching set. On older Windows releases, manually
remove `%LOCALAPPDATA%\gantry\assets\<version>`—deleting
`%USERPROFILE%\.gantry` does not remove that separate OS cache.

For an air-gapped or managed installation, stage all matching assets and point
Gantry at the directory:

```console
$ export GANTRY_ARTIFACTS=/opt/gantry/assets
```

Do not bypass checksum failures by renaming an unverified file to a default
asset name.

## An OCI image does not refresh

Normal `start` and `exec` prefer a verified cached tag. Refresh it explicitly:

```console
$ gantry image pull IMAGE:TAG
```

Inspect the selected digest and architecture:

```console
$ gantry image ls
```

Use a digest-pinned reference when reproducibility matters.

Current builds stage pulled layers under the private
`~/.gantry/images/tmp` directory. If an older Windows build reports access
denied below `%LOCALAPPDATA%\Temp\gantry-image-*`, update Gantry and retry;
`GANTRY_IMAGES` can also select an explicitly user-owned cache root.

## A stopped sandbox says its image is missing

The cached digest was removed after the sandbox was created. Pull its recorded
reference again:

```console
$ gantry image pull IMAGE:TAG
$ gantry resume dev
```

If the tag now resolves to a different digest, recreate the sandbox or use the
original digest-pinned reference. A writable layer is paired with its original
image identity and should not be silently reused with different content.

## Resume cannot find a secret

Only secret names persist. Export every configured value in the shell running
`resume`:

```console
$ export GITHUB_TOKEN=...
$ gantry resume dev
```

Use `gantry ls` or the dashboard Secrets view to see configured names. Gantry
does not display values.

## Network access is blocked

Inspect the effective policy:

```console
$ gantry net-policy show dev
```

Common causes are:

- the default local-network wall blocks a host, LAN, or metadata address;
- a default-deny policy lacks the destination or its DNS name;
- a domain allowlist does not include a redirect, authentication, or download
  host;
- the application uses an address directly, so a DNS allowance never learns
  it;
- the guest attempts IPv6, while the embedded network is IPv4-only;
- proxy enforcement blocks direct web traffic as configured.

Use the dashboard Traffic and Packets views to inspect decisions. Prefer a
narrow policy correction to `-allow-local-net`.

## A published port is unreachable

List the actual mapping, especially when Gantry selected the host port:

```console
$ gantry ports ls dev
```

Confirm that the guest service listens on the guest port and not only on guest
loopback. Port publishing requires networking and the embedded stack; it is
not available with `-net=false` or `-gvproxy`.

The default host bind is `127.0.0.1`. Use an explicit address only when remote
hosts must connect.

## A live share cannot be removed

Processes may still hold open files or directories. Stop those processes and
retry:

```console
$ gantry share remove dev TAG
```

If the guest is unresponsive and immediate revocation is acceptable:

```console
$ gantry share remove --force dev TAG
```

Forced removal can make existing guest handles fail. It does not delete host
files.

## The writable layer reports filesystem errors

Stop the sandbox before inspecting or repairing its ext4 file. Never attach
the layer to another running VM.

If its contents are disposable, deleting and recreating the sandbox is the
safest clean start:

```console
$ gantry delete dev
$ gantry start dev -image IMAGE
```

This removes the Gantry-managed default layer. If the sandbox uses an explicit
`-rwlayer`, move or remove that file yourself while the sandbox is stopped.

If the contents matter, copy the layer file before using an offline ext4
repair tool. Gantry does not provide snapshots or rollback.

## Strict process isolation refuses to start

`-process-isolation=required` fails when any required worker boundary cannot
be established or verified. Inspect `isolation.json` and the worker logs for
the exact property.

On Linux, restricted user namespaces, unavailable Landlock (Linux before
5.13), or seccomp policy imposed by an outer container can prevent the full
topology. Run Gantry directly on the host or enable the required kernel
features. Do not switch to `off` unless the weaker boundary is acceptable.

On Windows, strict mode requires brokered WHPX and, when networking is enabled,
the embedded split network worker. `-net=false` remains compatible with the
split VMM. AppContainer network isolation cannot use host loopback without a
privileged machine-wide exemption, which Gantry does not install. Remove
published ports and loopback-allowing policy rules, or use `auto` and inspect
the reported fallback. `-gvproxy` and host-path packet capture are also
incompatible with strict mode.

## Collect a useful report

Include:

- `gantry version` output;
- host operating system and architecture;
- the command with secret values removed;
- `sandbox.json` with sensitive paths reviewed;
- `isolation.json`;
- relevant daemon, console, and worker log tails.

Do not publish credential files, secret values, writable-layer contents, or
private project data. Report suspected sandbox-boundary vulnerabilities
privately using [SECURITY.md](../../SECURITY.md).

## Guest helper changes do not appear in the sandbox

`gantry-guest` (the credential helper and `oauth login` mode) is delivered
into the guest at every sandbox start from a host-side asset. In a source
checkout the asset resolves to `artifacts/gantry-guest-arm64` (or
`-x86_64`) — note there is no `linux` in the file name. Rebuilding to a
differently named file leaves the sandbox delivering the stale copy:

```console
$ GOOS=linux GOARCH=arm64 go build -o artifacts/gantry-guest-arm64 ./cmd/gantry-guest
$ gantry start demo ...   # restarts re-deliver
```

The delivery verifies the guest copy against the host file's SHA-256, so a
mismatch is logged loudly in `daemon.log`; compare `sha256sum` of
`/run/gantry/bin/gantry-guest` in the guest against the host artifact when
in doubt.
