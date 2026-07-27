# Gantry Quality and Architecture Review

Review date: 2026-07-27  
Revision reviewed: `6ef4824`

## Overall assessment

Gantry has a strong VMM core and sensible package boundaries, but it should currently be treated as a pre-production beta rather than a production-ready security boundary. The architecture is promising; several concrete isolation, lifecycle, and concurrency defects need resolution first.

## Priority findings

### 1. Critical: read-only filesystem shares are writable

The FUSE mutation opcode table in [`internal/virtio/vfs.go`](internal/virtio/vfs.go#L133) uses incorrect values for `SETXATTR` and `REMOVEXATTR` compared with the vendored [`third_party/go-fuse/fuse/opcode.go`](third_party/go-fuse/fuse/opcode.go#L16). As a result, those mutation requests are not rejected while harmless operations are misclassified.

The `OPEN` check also considers only the access-mode bits. `O_RDONLY | O_TRUNC` therefore passes the gate and can truncate a host file through the supposedly read-only share. Current tests cover ordinary read/write flags and common mutation requests, but not truncation, extended attributes, or newer mutation opcodes.

This directly contradicts the read-only guarantee described in the sandboxing documentation. The gate should use the shared opcode definitions where possible, reject every write-affecting open flag, default-deny unsupported mutation operations, and gain end-to-end regression tests for these cases.

### 2. High: a malicious guest can trigger guest-RAM-sized host allocations

Virtqueue validation permits descriptor totals up to the entire VM memory allocation in [`internal/virtio/virtio.go`](internal/virtio/virtio.go#L366). Several devices then allocate buffers from those guest-controlled lengths, including [`internal/virtio/vfs.go`](internal/virtio/vfs.go#L219), [`internal/virtio/vnet.go`](internal/virtio/vnet.go#L194), and [`internal/virtio/vvsock.go`](internal/virtio/vvsock.go#L216).

A malicious or compromised guest can consequently force one or more allocations approaching the guest RAM size. Device-specific protocol limits are needed for network frames, block segments, FUSE messages, vsock packets, and RNG requests. Malformed chains should be rejected without allocating their declared total size.

### 3. High: one-shot OCI execution has incorrect semantics

Although the CLI resolves image configuration in [`exec.go`](exec.go#L146), `client.Shell` drops `ImgCfg` and substitutes `/bin/sh` in [`internal/client/client.go`](internal/client/client.go#L674). Consequently, image entrypoint, command, environment, user, and working directory are not applied as advertised.

The task exit status is also discarded, meaning commands such as `gantry exec -- false` can return success. `Shell` should propagate the image configuration and return or capture the task status. CLI-level tests should cover image defaults, environment, user, working directory, and non-zero exits.

### 4. High: the image cache is unsafe under concurrent builds

[`internal/image/store.go`](internal/image/store.go#L130) deletes every `.erofs.tmp` file before taking a per-digest lock. A process building one digest can therefore remove another process's live temporary file. The shared `index.json.tmp` and read-modify-write index path can also lose entries when different digests are built concurrently.

The store needs a global index transaction lock, unique temporary files, and digest-scoped or lock-aware cleanup. Content metadata should be owned by its digest, while reference metadata should be updated atomically in the index.

### 5. High: stopping a VM is effectively a persistent-disk power cut

The daemon exits immediately on termination in [`internal/sandbox/sandbox.go`](internal/sandbox/sandbox.go#L337), while the backend contract in [`internal/vmm/machine.go`](internal/vmm/machine.go#L475) lacks cancellation, shutdown, or `Close` semantics. Block-device `Close` exists but is not invoked during normal shutdown.

This makes writable-layer corruption an expected failure mode. The lifecycle should support a guest sync or shutdown request, bounded graceful waiting, device flush and close, backend cleanup, and forced termination only as a fallback.

### 6. Medium: private image and writable-layer data uses permissive modes

The image cache requests `0755` directories and `0644` files in [`internal/image/store.go`](internal/image/store.go#L149). Writable layers use similar permissions in [`internal/sandbox/rwlayer.go`](internal/sandbox/rwlayer.go#L52).

Private registry contents, OCI environment metadata, and persistent filesystem data should normally use `0700` directories and `0600` files. Existing installations should have their modes tightened during migration or first use.

### 7. High: dependencies need immediate patch updates

`govulncheck ./...` reported eight symbol-reachable advisories:

- Three in the Go 1.26.3 standard library: `GO-2026-5856`, `GO-2026-5039`, and `GO-2026-5037`.
- Five through `golang.org/x/crypto v0.51.0`: `GO-2026-5020`, `GO-2026-5019`, `GO-2026-5018`, `GO-2026-5017`, and `GO-2026-5013`.

Upgrade Go to at least 1.26.5 and `golang.org/x/crypto` to at least 0.52.0, then rerun the scan. Symbol reachability does not by itself prove runtime exploitability, but these are straightforward security updates.

## Architecture assessment

The strongest aspects are:

- Clear separation among VMM backends, virtio devices, sandbox orchestration, image handling, and network policy.
- A unified `RunConfig`, which reduces configuration drift between execution modes.
- Network policy enforcement below the guest and host-side filesystem containment, which are the correct architectural layers.
- Good explanatory comments that preserve important behavioral context.
- Strong driver-simulation coverage in the virtio, image, and network-policy packages without requiring KVM.

The largest architectural debt is in `internal/sandbox`, which currently owns persistence, daemon lifecycle, locking, broker behavior, and control-plane details. A versioned control protocol and an explicit machine/device lifecycle would make this substantially easier to evolve and test safely.

The forked `go-fuse` module is also part of the security boundary. Its patches and tests should be tracked deliberately because root-level `go test ./...` does not automatically execute the nested module's test suite.

## Quality and verification

The following checks passed:

- `gofmt`
- `go vet ./...`
- `go test -count=1 ./...`
- Linux amd64 build
- Linux arm64 build
- Darwin arm64 build
- Windows amd64 build

Coverage is strongest in the data-plane packages and weakest in the control plane:

| Package | Coverage |
| --- | ---: |
| `internal/vnet` | 80.0% |
| `internal/netpol` | 77.7% |
| `internal/auth` | 73.5% |
| `internal/image` | 72.5% |
| `internal/virtio` | 70.0% |
| `internal/vmm` | 40.2% |
| `internal/sandbox` | 25.1% |
| `internal/client` | 9.3% |

`go test -race ./...` did not pass. It found a test-side concurrent access to a `bytes.Buffer` in [`internal/sandbox/security_test.go`](internal/sandbox/security_test.go#L49), and the virtio vsock handshake test timed out under race instrumentation. The current [CI workflow](.github/workflows/ci.yml#L20) does not run the race detector, so the repository's claim that the race suite is clean is not presently enforced or reproducible.

## Recommended remediation order

1. Fix the read-only filesystem gate and add regression tests for every mutation path.
2. Add per-device virtqueue size limits and adversarial descriptor-chain tests.
3. Upgrade the Go toolchain and vulnerable dependencies.
4. Correct one-shot image configuration and exit-status propagation.
5. Serialize image-store transactions and make temporary files unique.
6. Tighten persistent-data permissions.
7. Introduce graceful VM and device lifecycle APIs, then separate the sandbox control plane from persistence and process supervision.

