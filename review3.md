# gantry — architecture & code quality review

*Reviewed at `570e25e` (clean tree). Follow-up to `review2.md`; this one
does not repeat items that have since been fixed.*

## What changed since the last review

Almost everything the previous review put in its priority list has landed,
and landed well:

- The package split happened. `internal/{vmm,virtio,client,sandbox,netpol,vnet,gutil}`
  with a declared `backend` interface in `machine.go` and one implementation
  per build tag. `Device` is a clean interface and the machine no longer
  knows what a device is.
- The virtio-fs escape is closed on both vectors, the vendored patches are
  documented at the top of `vfs.go`, and the PoC is now an assertion
  (`TestVirtioFSShareEscape`, `TestVirtioFSSymlinkEscapeBlocked`).
- `,ro` is enforced host-side in `roFuseHandler`, which is the right layer.
- virtio-blk returns descriptors on every error path; `descAt` bounds-checks
  against guest RAM before anything allocates.
- `handleMMIO` is a flat sequence of range checks.
- `gofmt` is clean, `go vet` is clean, all tests pass.

The device model is no longer written for a cooperative guest. That was the
headline problem and it is largely fixed. What follows is the next layer down.

---

## 1. Bugs

### 1.1 Egress policy: any destination ending in `.255` bypasses every rule

`netpol/policy.go:304`

```go
if dst.Equal(net.ParseIP(gatewayIP)) ||
    dst.Equal(net.IPv4bcast) || strings.HasSuffix(dst.String(), ".255") {
    return p.matchGatewayService(pp)
}
```

`matchGatewayService` returns `true` for everything except a name-filtered
DNS query. So the suffix test hands a full pass to any unicast address whose
last octet happens to be 255 — `8.8.8.255`, `52.1.2.255`, anything. It
short-circuits the rule list, the local-network wall, and the default action.

Confirmed against the current code with a scratch test: a `{"default":"deny"}`
policy allows `tcp 8.8.8.255:443`.

The subnet is fixed and known (`vnet.SubnetCIDR`, 192.168.127.0/24), so the
directed-broadcast case is exactly one address. Compare against that instead
of string-matching the last octet:

```go
if dst.Equal(gatewayAddr) || dst.Equal(net.IPv4bcast) || dst.Equal(subnetBroadcast) {
```

`policy_test.go:121` covers `255.255.255.255` for DHCP, which is why this
didn't show up.

Related and much smaller: `parseFrame` sets `dport = 0` for non-first
fragments (`policy.go:281`), so a rule carrying a `Ports` list can't match
them and they fall through to the default. Under default-deny that fails
closed; under a default-allow policy with deny-by-port rules, fragmenting
evades the rule. Worth a line of comment at minimum, since the current
comment ("treat proto-only") reads as if it were the intended behaviour
rather than a known gap.

### 1.2 `gantry start -rw` with no rwlayer produces a VM that can't mount its root

`sandbox.go:241`

```go
cfg.RW = *rw || (!rwSet && cfg.RWLayer != "")
if !rwSet && cfg.RWLayer == "" {
    cfg.RW = false
}
```

If `-rw` is passed explicitly and no rwlayer exists, `cfg.RW` stays true with
`cfg.RWLayer == ""`. The existence check two lines down is guarded by
`cfg.RWLayer != ""` and doesn't fire. The daemon then builds `disks` without
a `/dev/vdc` (`sandbox.go:422` has the same `RWLayer != ""` guard) but hands
`RW: true` to `client.Session`, so `RootfsMounts(true)` asks the guest to
mount `/dev/vdc` — which isn't attached. The user gets a mount failure from
inside the VM instead of a CLI error.

`exec.go:122` gets this right (`if rwl == "" { rw = false }`). The two code
paths disagree because they are separate copies — see §2.1.

### 1.3 Sandbox control sockets are world-connectable

`sandbox.go:275` creates `~/.gantry/sandboxes/<name>/` with mode 0755, and
`net.Listen("unix", …)` creates `ctl.sock` with 0755 & umask. On a
multi-user host, any local user can connect to the broker and get a root
shell inside the sandbox — including whatever host directories `-share`
exported read-write. `listen-1026.sock` (the raw guest stream port) and
`1025.sock` are equally exposed.

There's no authentication in the broker protocol, and there doesn't need to
be: `0o700` on the sandbox directory is the whole fix.

`gantry exec`'s one-shot path is already fine — it uses `os.MkdirTemp`,
which is 0700.

---

## 2. Architecture

### 2.1 The same 60 lines of option resolution exist three times

`runExec` (exec.go:32), `CmdStart` (sandbox.go:135) and `CmdDaemon`
(sandbox.go:333) each independently implement:

- the `crun`/`runsc` switch with `GvisorRootfs`/`GvisorKernel` fallbacks and
  their two "not found, build it with …" messages
- the `debian-bookworm.erofs` → `shell-rootfs.erofs` image default
- the `rwlayer.ext4` default and the `-rw` defaulting rules
- the `fs.Visit` "was this flag set explicitly?" dance, four times over
- policy construction (`netpol.Load` → `AllowLocal` → `DefaultPolicy`) and
  its two "requires the embedded netstack" conflict checks
- share-spec parsing
- `netMarker`, which is copied verbatim into two packages (`exec.go:323`,
  `sandbox.go:884`)

Bug 1.2 is a direct consequence: one copy grew a guard the others didn't.
The natural shape is a `type runConfig struct` with one `resolve(flags) (runConfig, error)`
and one `func (c runConfig) opts() vmm.Opts`, shared by all three entry
points. That also gives `sandbox.json` an obvious identity — it is a
serialized `runConfig` — instead of being a third, slightly different
struct.

### 2.2 `internal/sandbox` is really `internal/cli`

It holds the sandbox lifecycle (a legitimate library concern) plus flag
parsing, usage strings, `fmt.Fprintf(os.Stderr, "gantry start: …")`, `int`
exit codes, and `os.Exit(2)` inside `CheckedSandboxName` (`sandbox.go:112`).
A library that calls `os.Exit` can't be tested or reused, and the exit is
load-bearing for path-traversal safety, which is a lot of weight on a
side effect.

Split: `CheckedSandboxName` → `ValidateSandboxName(name) error` with the
exit at the `main.go` dispatch; presentation (usage text, error prefixes,
exit codes) up into the CLI layer; the broker, daemon, and lifecycle stay
where they are.

### 2.3 Guest console output goes through package globals

`machine.go:32` — `consoleWriter` and `stdoutBuf` are package-level mutable
state, configured by `SetConsoleWriter` before boot. Two consequences:

- Only one VM can exist per process. `Prepare` otherwise looks like it
  supports many.
- `stdoutBuf` is appended under the UART's own mutex, but `stdoutFlush()` is
  called from PSCI/shutdown paths on other threads (`vm_darwin.go:584`,
  `kvm_amd64.go:292`, `vm_linux.go:187`) without it. It's a shutdown-path
  race on a `[]byte`, so it will almost never bite, but `-race` would
  eventually find it.

Both go away by moving the writer and buffer onto `Machine` and giving the
console its own small mutex.

### 2.4 `client.Session` and `ensureSandboxContainer` are two copies of one flow

`client.go:180` and `client.go:440` both do bundle-create-with-"file exists"-
fallback, share mounting with identical logging, stream opening, `Create`,
and race recovery — with three different sets of retry conditions between
them (`already exists`, `busy`/`in-use` + poll, plus a third variant inline
in `Session`'s error handler). The recovery logic is subtle and hard-won;
having it in three places is how it drifts.

Extract `ensureBundle(ctx, id, cfg) (string, error)` and
`mountShares(ctx, shares) error`, and give the race recovery one named
helper (`awaitRunning(ctx, id) bool`) rather than three inline 50-iteration
loops.

Related: matching ttrpc failures with `strings.Contains(err.Error(), "file exists")`
is fragile, but vminitd doesn't return typed errors, so it's the only option.
Worth one comment saying so, and worth collecting the string constants in one
place instead of five call sites.

### 2.5 Small structural leftovers

- `Machine.devBase` / `devStride` are assigned in `Prepare` and never read;
  `devIRQ` is never even assigned (`machine.go:154-156`). Delete all three —
  the per-device values live on `virtio.Core` now.
- `client.ShareEntry` (client.go:49) and `vmm.ShareManifestEntry`
  (share.go:32) are the same struct maintained by hand in two packages,
  connected only by a comment and a JSON file. One of them should import
  the other, or both should import a tiny `internal/shares`.
- `client.LoadShares(rpcSock)` takes a socket path and internally does
  `filepath.Dir` to find `shares.json`. Take the directory.
- `CmdSandboxExec`'s ctrl-C handler consumes exactly one signal
  (`sandbox.go:678`), so a second ctrl-C is silently ignored for the rest of
  the session. `for range sigc` is the fix.

---

## 3. What's good

Unchanged from the last review and still true: the comments are the best
thing here, because they record symptoms rather than restating code — the
THRE-as-level-condition note, the vsock eventq interrupt storm, the
"contiguous frame" corruption, the `nohup`+stdio-detach explanation on
`containerInitArgs`, the HVF thread-affinity and vCPU-creation-ordering
notes. Someone picking this up in a year will be able to.

Two new things worth calling out:

- `netpol` is a well-shaped package: the enforcement point is stated in the
  package doc and is genuinely unbypassable from the guest, the local-network
  wall sits deliberately *before* the DNS-learned table (with the DNS-rebinding
  reasoning written down), and it's tested at both the policy level and on
  the wire (`vnet_policy_test.go`).
- The 36 tests still need no hypervisor and cover the hard parts. The
  transport-level security tests (`TestQueueNumClamp`,
  `TestGiantDescriptorRejected`) are the right kind of regression test for
  this codebase.

---

## 4. Housekeeping

- **`crunshim`, a 2.4 MB Linux binary, is committed at the repo root.** It's
  built from source by `mkrootfs-gvisor.sh:38` and is not referenced by any
  script as a checked-in artifact, so it's a stray `go build` output. Add it
  to `.gitignore` and `git rm --cached`.
- **No CI.** `go vet` and `go test ./...` both pass and the test suite needs
  no KVM and no root — this is about ten lines of GitHub Actions and it would
  have caught the `virtio_test.go` compile break mentioned in the last review.
- **`cmd/hostctl` is a separate Go module** (`replace gantry => ../..`) whose
  dependency versions have already drifted from the root module —
  `golang.org/x/term` v0.45 vs v0.43, `golang.org/x/net` v0.56 vs v0.55, and
  it lists direct dependencies as `// indirect`. Nothing in the tool needs
  module isolation; folding it into the root module removes a maintenance
  surface.
- **`vsock.pending` is unbounded** (`vvsock.go:387`). `pumpHost` appends
  host→guest payloads with no cap while `tryFlush` can stall indefinitely on
  guest credit or on the guest posting no rx buffers. virtio-net already caps
  at `virtioNetMaxQueue`; vsock should do the same and drop-with-RST past the
  limit.
- **`sandboxPID` trusts a recycled pid.** `procAlive(pid)` on a stale pid file
  reports "running" if the OS reused the number. Writing the daemon's start
  time alongside the pid, or holding a lock file, would make it exact. Low
  priority — the failure mode is a confusing error, not damage.
- `todo.md` and `review2.md` are working notes committed to the repo root.
  Fine as a deliberate choice, worth moving under `docs/` if it isn't.

---

## 5. Suggested priority

1. **§1.1 the `.255` policy bypass** — it silently defeats the feature whose
   entire purpose is being a boundary.
2. **§1.3 directory mode 0700** — one-line fix, removes local-user access to
   a root shell with the sandbox's host shares.
3. **§1.2 the `-rw` inconsistency** — small, user-visible, and it disappears
   for free with §2.1.
4. **§2.1 one shared option-resolution path** — the change that stops the
   three CLI entry points from drifting further apart.
5. **§4 CI + `.gitignore` for `crunshim`** — cheap, and CI is what keeps the
   rest of this list from regressing.
