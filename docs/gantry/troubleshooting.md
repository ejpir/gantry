# Troubleshoot Gantry

Start with the command error and sandbox logs. Gantry keeps current and previous
daemon diagnostics after failed starts.

## Find sandbox logs

```console
$ cd "$HOME/.gantry/sandboxes/dev"
$ tail -n 200 daemon.log
$ tail -n 200 console.log
$ tail -n 200 worker-vmm.log
$ tail -n 200 worker-net.log
```

`daemon.log.previous` contains the prior boot when available.
`isolation.json` records the effective worker topology and confinement checks.
If `GANTRY_HOME` is set, use `$GANTRY_HOME/dev`.

## The hypervisor is unavailable

### Linux

```console
$ ls -l /dev/kvm
$ test -r /dev/kvm -a -w /dev/kvm && echo OK
```

Enable virtualization in firmware and nested virtualization when running
inside another VM. Group changes usually require a new login.

### macOS

Only Apple silicon is supported. Release binaries include the
Hypervisor.framework entitlement; local builds may need signing with the
repository entitlement.

### Windows

Enable Windows Hypervisor Platform and ensure the machine or outer VM exposes
hardware virtualization. Include `worker-vmm.log` in reports.

## Guest assets cannot be downloaded

Gantry verifies each release asset with its SHA-256 sidecar. Check GitHub
Releases access and retry. For a deliberately rebuilt tag, run:

```console
$ gantry update --force
```

For an air-gapped installation, stage a matching asset set and configure:

```console
$ export GANTRY_ARTIFACTS=/opt/gantry/assets
```

Do not work around checksum failures by renaming unverified files.

## An OCI image does not refresh

Cached tags are reused. Refresh and inspect explicitly:

```console
$ gantry image pull IMAGE:TAG
$ gantry image ls
```

Use a digest when reproducibility matters.

## A stopped sandbox says its image is missing

Its cached digest was removed. Pull the recorded reference and resume:

```console
$ gantry image pull IMAGE:TAG
$ gantry resume dev
```

If the tag now points to another digest, restore the original digest or create
a new sandbox. Writable layers are tied to their original image.

## Resume cannot find a secret

Environment secret values do not persist. Export them in the shell running
resume:

```console
$ export GITHUB_TOKEN=...
$ gantry resume dev
```

`gantry ls` and the dashboard show names, never values. File-backed sources are
resolved again automatically.

## Network access is blocked

```console
$ gantry net-policy show dev
```

Check for:

- the default host/LAN/metadata block;
- a missing CIDR, port, protocol, DNS, redirect, or authentication host;
- direct-IP traffic that cannot use a DNS allowance;
- IPv6 from an application; or
- proxy enforcement blocking direct web traffic.

Use dashboard **Traffic** and **Packets** to inspect decisions. Prefer a narrow
rule over `-allow-local-net`.

## A published port is unreachable

```console
$ gantry ports ls dev
```

Confirm the guest service listens on the published guest port, not only guest
loopback. Publishing requires networking. UDP also requires the active policy
to permit `192.168.127.1:16000-65535/udp`.

Host loopback is the default bind. Use a non-loopback address only when remote
hosts must connect.

## A live share cannot be removed

Stop processes holding the mount and retry:

```console
$ gantry share remove dev TAG
```

Use `--force` only when immediate revocation is necessary. Existing guest
handles may then fail; host files are not deleted.

## The writable layer reports filesystem errors

Stop the sandbox and never attach its layer to another running VM. If contents
are disposable, delete and recreate the sandbox. If they matter, copy the
layer before using an offline ext4 repair tool. Gantry has no snapshot or
rollback support.

An explicit `-rwlayer` is caller-owned and is not removed by `gantry delete`.

## A policy feed does not update all sandboxes

Policy-feed diagnostics are written by the `gantry serve` process. Check that:

- the feed URL uses HTTPS and does not redirect;
- the service trusts the configured client certificate;
- the configured CA verifies the service hostname;
- the client-key file has owner-only permissions or a protected Windows ACL;
- the response organization and signed bundle match the locally pinned key and
  profile; and
- the generation increased without reusing an old number for different bytes.

A feed cursor advances only after every saved sandbox receives the generation.
The receiver continues with other targets and retries a partial rollout. Any
running target that cannot reconcile is stopped rather than left on the old
organization generation. `gantry policy show NAME` reports each saved revision;
a deliberately stopped sandbox is updated but not started.

## Strict process isolation refuses to start

`-process-isolation=required` fails when a worker property cannot be verified.
Inspect `isolation.json` and worker logs.

Linux requires usable user namespaces, Landlock, and seccomp. Windows strict
networking rejects host-loopback access and published ports. Use `auto` only if
the reported weaker boundary is acceptable.

On Apple M4/macOS 15, an older VMM Seatbelt profile can make
`hv_gic_create` return `HV_BAD_ARGUMENT` even though `kern.hv_support=1` and the
binary has the hypervisor entitlement. Hypervisor.framework reads
`hw.pagesize_compat` while creating the GIC on that platform. Current builds
allow that exact non-process-specific sysctl only in the VMM worker profile; no
broad sysctl, Mach-service, or IOKit permission is required.

## Guest helper changes do not appear

Source builds deliver `artifacts/gantry-guest-arm64` or
`artifacts/gantry-guest-x86_64` on every start. Rebuild the exact host-expected
name, for example:

```console
$ GOOS=linux GOARCH=arm64 go build \
    -o artifacts/gantry-guest-arm64 ./cmd/gantry-guest
```

A hash mismatch appears in `daemon.log`.

## A macOS sandbox lags under compilation load

Resume with cumulative virtio-fs and Hypervisor.framework statistics enabled:

```console
$ GANTRY_VHOST_STATS=1 GANTRY_HVF_STATS=1 gantry resume dev
$ tail -f "$HOME/.gantry/sandboxes/dev/daemon.log" \
    "$HOME/.gantry/sandboxes/dev/worker-vmm.log"
```

`vhost-share-stats` reports FUSE operation count and latency.
`vhost-fs-call-stats` reports completion-interrupt delivery. `hvf-stats` reports
GIC call latency and assertion/deassertion counts per IRQ, production
liveness-kicker calls and targets per vCPU, other cancellation kicks, canceled
exits, and the current age of vCPUs inside `hv_vcpu_run`. These counters are
cumulative and the HVF reporter does not force exits or log once per interrupt.

For small probes, `GANTRY_VHOST_STATS_EVERY=N` (1..25000) lowers the
`vhost-share-stats` cadence, and `GANTRY_VHOST_TRACE=1` additionally logs the
first 600 LOOKUP/GETATTR/STATX requests with their on-wire entry/attribute
timeouts. The trace answers "is the guest told it may cache this?" without a
kernel build. A `sharefs-ttl` line per export records the chosen TTL plus
notification-channel and watcher health; `vhost-share-notify` records reverse
notification sink attach/detach.

`GANTRY_FUSE_MAX_BACKGROUND=N` (1..128) overrides the FUSE background-request
window advertised at INIT (default 12, congestion at 3/4). Measured on an
M4 GoReleaser workload it made no difference — synchronous compiler I/O rarely
exceeds 12 in flight — so keep the default unless a profile says otherwise.

### Metadata caching on shared mounts

The share server answers metadata with two TTLs: 100ms while coherence is
weak, one hour once both the reverse notification virtqueue and the host file
watcher are healthy. The hub root and export roots historically served TTL 0
so share hot-add/remove appeared immediately; current builds cache them too
once reverse notifications are live, because namespace changes already push
dentry invalidations over that channel. On an M4 `task build` of a Go CLI this
removed ~165k metadata round trips per build (275k to 110k requests) and cut
the warm capped build from ~184s to ~157s. If a share ever looks stale, check
for `sharefs-ttl` lines: `notifications=false` or `watcher-healthy=false`
means the short TTL is deliberate and the long one is unsafe.

To A/B repeated device assertions on macOS, add
`GANTRY_HVF_IRQ_COALESCE=1`. It suppresses a repeated GIC line level until the
guest's interrupt acknowledgement supplies the opposite transition;
`hvf-stats` includes the suppressed total and renders each IRQ as
`assertions/deassertions/suppressed`. This is a diagnostic switch, not a
production default.

If the reporter stops producing lines while the VM lags, a liveness kick may
be blocked inside Hypervisor.framework while holding the vCPU registry lock.
Newer `hvf-stats` lines show `in-flight=<age>` and `vcpu-lock=busy` without
waiting for that lock. As a final A/B only, `GANTRY_HVF_NO_LIVENESS_KICK=1`
disables the lost-vtimer backstop. Do not use that setting normally: a host
with the original missed-vtimer failure can leave Linux CPUs without scheduler
interrupts or RCU progress.

## Collect a useful report

Include:

- `gantry version`;
- host OS and architecture;
- the command with secrets removed;
- reviewed `sandbox.json` and `isolation.json`; and
- relevant daemon, console, and worker log tails.

Do not publish credentials, secret values, writable-layer contents, or private
project data. Report possible boundary vulnerabilities privately through
[SECURITY.md](../../SECURITY.md).
