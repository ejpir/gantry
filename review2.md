# gantry — architecture & code quality review

*Reviewed at commit `3d4fb54` plus the uncommitted working tree. Note: the tree
was being actively edited during the review — `virtio_test.go` did not compile
(lines 753, 762) and `third_party/go-fuse/fs/bridge.go` changed mid-read, so
line references are approximate.*

## Headline

The VMM core is genuinely good work. The boot protocols, the device model, and
especially the commentary explaining *why* each workaround exists are better
than most hobby VMMs and better than plenty of production ones.

The problem is a systematic one, and it is the same problem in six places: **the
device model is written as if the guest were cooperative, and this is a product
whose entire purpose is running guests that aren't.**

The virtio-fs escape in the working-tree PoC reproduces:

```
LOOKUP "../OUTSIDE-SECRET" resolved to nodeid 2 (outside the share)
SHARE ESCAPE CONFIRMED: read host file outside the share.
```

---

## 1. Security: the trust boundary

### 1.1 The share escape, and why the in-progress fix isn't finished

`vfs.go` hands guest-written bytes straight to go-fuse's `rawBridge`, and
`LoopbackNode.Lookup` (`third_party/go-fuse/fs/loopback.go:130`) does
`filepath.Join(n.path(), name)`. Upstream go-fuse is safe because its only
client is the host kernel's FUSE driver, which never emits `..`. Gantry's client
is a hostile guest writing the wire directly.

The `validGuestName` guard being added to `bridge.go` is at the right layer and
covers the right operations. Two gaps remain.

**It lives in vendored third-party code.** A re-vendor silently drops it, and
nothing in gantry's own test suite asserts the property — the only test is the
PoC, whose own header says to delete it once fixed. Flip the PoC to assert
`EINVAL` instead of deleting it, and add a comment in `vfs.go` pointing at the
patch.

**The symlink vector survives.** `Open` is safe: it uses
`openat.OpenSymlinkAware` against the root (`loopback.go:378`). But the
path-based operations are not — `Symlink`, `Mkdir`, `Mknod`, `Unlink`, `Rmdir`,
`Setattr`, `Getattr` and the xattr ops all build `filepath.Join(n.path(), name)`
and call path syscalls that follow *intermediate* symlinks. A guest issues
`Symlink(target="/", name="evil")` — the target is not validated, and correctly
cannot be — then descends through `evil` component by component. That is
create/unlink/chmod anywhere the gantry uid can reach.

The real fix is holding an `O_PATH` fd for the share root and using `*at`
syscalls or `openat2(RESOLVE_IN_ROOT)` throughout the loopback, rather than
string joins.

### 1.2 `,ro` shares are not a boundary at all

`share.go` is honest about this — the comment states that enforcement happens in
the guest, via hostctl's `MS_RDONLY` and the OCI `ro` bind mount. A hostile
guest simply does not run hostctl. So `-share code=$HOME/repos,ro`, which the
README advertises, is read-write.

`virtioFS` already knows `share.ro`; gating the mutating FUSE opcodes there is a
small change and makes the flag mean what users read it to mean. If that's not
wanted, say so in the README next to the flag.

### 1.3 Guest-controlled host allocation

Capping `d.len` at RAM size in `descAt` was the right instinct but doesn't
finish the job. `readChains` (`virtio.go:416`) and `readIOV`/`out` in
`vfs.go:123,160` still allocate per descriptor *before* the address is
validated, and chains run to ~65 descriptors. On a 512 MiB guest that is ~32 GiB
of host allocation per request, repeatable.

Validating `addr+len` against RAM inside `descAt` makes the allocation
inherently bounded and is a one-line change; a total-bytes-per-chain cap on top
is cheap insurance.

---

## 2. Correctness bugs

**virtio-blk leaks descriptors** — `vblk.go:94` and `:98`. Both error paths
`continue` without `pushUsed`, so the head is popped off the avail ring and
never returned. The guest driver waits forever on that request, and repeated
hits drain the ring. This is exactly the bug class just fixed in
`vvsock.tryFlush`; worth grepping every `handleQueue` for the same shape.

**Asymmetric offset check in virtio-blk.** The write path guards `off < 0`
(`vblk.go:144`); the read path does not (`:115`), so a large guest-supplied
`sector` overflows `int64(sector*512)` negative. It degrades safely today
because `ReadAt` rejects negative offsets, but the asymmetry looks accidental
rather than reasoned.

**Ignored error** on the status-byte write at `vblk.go:169` — the only unchecked
`mem.writeAt` in the tree.

---

## 3. Architecture

### 3.1 Everything is `package main`

45 files, ~8.6k LOC, spanning the CLI, sandbox lifecycle and daemon broker, the
device model, three hypervisor backends, and two boot protocols. Nothing is
encapsulated from anything.

The cost is visible in the code: the `pushUsedProbe` test hook is a package
global (`virtio.go:353`), console output goes through mutable globals
(`machine.go:28`), and debug env flags are scattered as globals across six
files.

Splitting out `internal/virtio`, `internal/vmm` and `internal/sandbox` is the
highest-leverage structural change available. The device model would move nearly
unchanged because `virtioDevice` is already a clean interface. It would also
give one obvious place to state the guest/host trust boundary, which is
currently implicit everywhere and therefore enforced nowhere.

### 3.2 Backends are four independent `runGuest` functions

Selected by build tag, with no declared interface (`vm_linux.go:23`,
`kvm_amd64.go:110`, `vm_darwin.go:194`, `whpx_windows.go:180`). It keeps files
small, but nothing states what a backend must provide, so writing a fifth one
means discovering the contract through build errors. A `type backend interface`
plus per-file constructors would cost very little.

### 3.3 Device work runs on the vCPU thread under `core.mu`

`vblk` does file I/O and `virtioFS` runs an entire FUSE operation synchronously
inside `handleQueue`, called from `mmioWrite` with the transport lock held. A
slow host filesystem stalls that vCPU.

That is an acceptable tradeoff for a dev tool, and worth knowing before it is a
product. vsock already learned this the hard way — see `vvsock.go:297` and the
comment above it.

### 3.4 `handleMMIO` control flow

`machine.go:202`: the IO-APIC range check sits *after* the switch and is
reachable only by falling out of the `default:` branch. It works, but it reads
as an accident. A flat sequence of range checks, or a small sorted region table,
would say what it means.

---

## 4. What's good, and worth protecting

The comments are the best thing in this codebase. They record concrete failure
symptoms rather than restating the code: the THRE-interrupt note explaining the
"second exec hangs" bug, the PL011 RIS-offset storm, the vsock eventq ping-pong,
the contiguous-frame corruption. That is institutional memory most projects
lose.

The README is a real design document.

The 32 tests are driver-simulation style and need no KVM, covering the genuinely
hard parts — MPS tables, page tables, x86 instruction decode, the vsock
handshake, FDT SMP.

The uncommitted diff is uniformly good: ELF header bounds checks, the QueueNum
clamp, PIC/CMOS mutexes for SMP, the pumpOut done-channel, the rx descriptor
leak fixes.

---

## 5. Housekeeping

- `gofmt -l` flags `bootx86.go`, `vvsock.go`, `guest/init/main.go`.
- A 15 MB build artifact is committed at `cmd/hostctl/hostctl`. `.gitignore`
  catches `/hostctl` at the root but not that one.
- The rename-migration message at `sandbox.go:72` prints
  `~/.gantry -> ~/.gantry`.
- `cmdStop`'s comment says it keeps `sandbox.json` "so `start` can recreate",
  but `cmdStart` does `os.RemoveAll(dir)` and rebuilds config from flags. That
  file is only ever read by `cmdDaemon` and `cmdLs`.
- README "Honest gaps" is the right instinct but lists missing *features* (no
  DAX, no snapshotting), not the thing a reader most needs to know: that the
  device model currently assumes a cooperative guest, and what that means for
  `-share`.

---

## 6. Suggested priority

1. **The symlink half of the virtio-fs escape** and **`,ro` non-enforcement** —
   these two change what the product can safely be pointed at.
2. **The virtio-blk descriptor leak** — most likely to bite a real user today.
3. **Bounded descriptor allocation** in `descAt` — cheap, closes a host DoS.
4. **Package split** — the structural change that makes the rest maintainable.
