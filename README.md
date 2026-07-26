# gantry

**gantry** is a tiny microVM monitor that boots Docker's nerdbox guest
(kernel + vminitd) and runs OCI containers in it — built from scratch by
reverse-engineering sbx/libsailor, mirroring its boot protocol, memory
layout, and device model. Linux KVM (arm64 + x86-64), macOS
Hypervisor.framework, and Windows WHPX.

*(named after the port crane that picks containers off the ship; formerly
"minivm" — old `MINIVM_*` env vars and a `~/.minivm` state dir still work
as fallbacks)*

## Status

| component | state |
|---|---|
| KVM backend (Linux/arm64) | ✅ builds; run on any host with `/dev/kvm` |
| KVM backend (Linux/x86-64) | ✅ **verified end-to-end on EC2 m6i.metal** (KVM/VMX): boot, SMP (2 vCPUs), multi-exec containers, virtio-net/DHCP, virtio-fs share, rwlayer persistence |
| WHPX backend (Windows x86-64) | ✅ builds (`gantry-windows-amd64.exe`); userspace IO-APIC/PIT/PIC + x86 MMIO decoder unit-tested; needs a real Windows box for the boot test |
| virtio-fs sharing | ✅ macOS/Linux; ❌ Windows (go-fuse port needed) |
| HVF backend (macOS arm64, Hypervisor.framework via purego) | ✅ verified end-to-end on Apple Silicon |
| SMP (`-cpus N`, ≤8) + `-mem` | ✅ HVF verified (4 vCPUs, PSCI CPU_ON per vCPU); ✅ KVM x86-64 verified (2 vCPUs via MPS + INIT/SIPI) |
| PL011 serial console (arm64) / 16550 + CMOS RTC (x86) | ✅ verified interactively under QEMU and HVF |
| virtio-mmio transport v2 + split virtqueues | ✅ unit-tested |
| virtio-blk (multi-disk) | ✅ ro boot rootfs; rw `-disk` (WRITE+FLUSH) for the ext4 rwlayer |
| virtio-vsock (guest dial-back + host listen) | ✅ ttrpc control + raw stdio streams work end-to-end |
| virtio-net (2 queues) | ✅ end-to-end via **embedded gvisor-tap-vsock netstack** (no gvproxy binary): DHCP, NAT, DNS, ICMP; external gvproxy over unixgram still supported (`-gvproxy`) |
| virtio-fs (go-fuse loopback, no DAX) | ✅ HVF end-to-end: multi-share + `,ro`; host dir live in container at `/host` |
| virtio-rtc (UTC, spec device ID 17) | ✅ hctosys at boot + vminitd PTP sync; apt/TLS see real time |
| virtio-rng | ✅ crng seeded at probe; no more getrandom boot timeouts |
| guest PID 1 (static Go) + busybox shell | ✅ verified under QEMU and HVF |
| nerdbox task.v3 + crun container | ✅ `Create` → `Start` → interactive container shell |
| FDT builder | ✅ kernel boots from it under QEMU |

## x86-64 guests (Linux/KVM)

The same binary family boots Docker's `nerdbox-kernel-x86_64` (a **vmlinux
ELF**, not a bzImage) + `nerdbox-rootfs-x86_64.erofs` on an x86-64 Linux
host with `/dev/kvm`:

- **Boot**: the 64-bit boot protocol (like QEMU's vmlinux loader) — PT_LOAD
  segments at their physical addresses, identity-mapped long mode (4 GiB,
  2 MiB pages), flat GDT, `rsi` → zero page with cmdline + e820
  (`bootx86.go`).
- **No ACPI**: a minimal **MPS v1.4 table** (floating pointer @ `0xf0000`,
  config table @ `0xf0100`) enumerates CPUs and the IO-APIC, laid out like
  kvmtool's: CPU/bus/IO-APIC entries + LINT0 (ExtINT) / LINT1 (NMI) and
  **no ISA→IO-APIC INT entries** — legacy IRQs (<16) stay in virtual-wire
  PIC mode, which is how our virtio-mmio device IRQs are delivered. (An
  INT entry for IRQ0 sends the kernel down the IO-APIC-timer path and it
  NULL-derefs in `check_timer`.) SMP comes up via in-kernel INIT/SIPI
  (APs stay `KVM_MP_STATE_UNINITIALIZED` until the guest's smpboot wakes
  them; `KVM_RUN` on a parked AP returns `EAGAIN` — retry, don't exit).
- **Devices**: the same virtio-mmio device model; the x86 kernel has
  `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y`, so devices are declared as
  `virtio_mmio.device=0x1000@0xc0000000+i*0x1000:IRQ` cmdline slots with
  IRQs `[3,5,6,7,9,10,11,12]` (legacy lines, IO-APIC identity map; IRQ 4 =
  serial). In-kernel irqchip + PIT; `KVM_IRQ_LINE` for injection; the
  virtio InterruptACK handler lowers the line so edge-triggered IO-APIC
  pins re-fire.
- **Console**: 16550A UART on port `0x3f8` IRQ 4 (`console=ttyS0`) via
  `KVM_EXIT_IO`. The THRE interrupt is modeled as a level condition
  (IER.1) — kernel printk uses the polling path and works without it,
  but userspace tty writes (vminitd's `/dev/console` logs) are THRE-IRQ
  driven and silently stall without it (this was the "second exec hangs"
  bug). A tiny MC146818 CMOS RTC answers the early-boot clock read
  (virtio-rtc + PTP still provide the real time source).
- **CPUID**: `KVM_GET_SUPPORTED_CPUID` → `KVM_SET_CPUID2`, so kvm-clock /
  paravirt features work.
- RAM limit 3 GiB (device window at `0xc0000000`).

Validated on **EC2 m6i.metal** (Ice Lake, VMX): kernel 7.0.12 boots,
`smp: Brought up 1 node, 2 CPUs`, EROFS root + image + ext4 rwlayer mount,
vminitd runs, back-to-back `exec` sessions work, embedded netstack DHCP/NAT gives
the container outbound TCP+DNS, virtio-fs shares mount at `/host`, and the
rwlayer persists across stop/start. Debug bring-up also covered
`KVM_EXIT_FAIL_ENTRY` from a zeroed TR/LDTR (GET→modify→SET SREGS instead)
and the shared `struct kvm_run` `exit_reason` being a u32, not u64.

Container images must match the guest arch: build them with
`./mkimage.sh IMAGE out.erofs linux/amd64` (needs an amd64
Docker context or cross-build).

## Windows guests (WHPX)

The Windows release (`DockerSandboxes.msi`) ships `sailor.dll`, the same
`nerdbox-rootfs-x86_64.erofs`, and **the same vmlinux embedded in the DLL**
(entry `0x27176b0`, identical PT_LOAD layout). Its strings show the design:
`WHvCreatePartition`/`WHvRunVirtualProcessor` (Windows Hypervisor
Platform), `virtio_mmio.device` cmdline transport, `console=ttyS0`, plus
userspace IO-APIC (`ioapic`×214) and i8254 PIT references — because WHPX,
unlike KVM, has no in-kernel irqchip or PIT (only the LAPIC is emulated
in-kernel).

`gantry-windows-amd64.exe` mirrors that architecture with the shared x86-64
machine model:

- **WHPX bindings** (`whpx_windows.go`): partition + `ProcessorCount`
  property, GPA mapping, per-VP threads; BSP starts in long mode with the
  same register state as the KVM backend; APs wait for INIT/SIPI (WHPX
  LAPIC delivers it).
- **Userspace irqchip**: IO-APIC (`ioapic.go`) at `0xfec00000` delivering
  via `WHvRequestInterrupt`; i8254 PIT (`pit.go`) ticking IRQ 0 for early
  boot; i8259 PIC stub (`pic.go`); the MPS table tells the guest how to
  route everything (shared with KVM x86).
- **MMIO exits need instruction decode** on WHPX (no operand value in the
  exit): `x86emul.go` decodes the mov-family Linux emits for device access
  (ModRM/SIB/REX, imm, movzx/movsx), unit-tested.
- Port-I/O exits give `RAX` directly — serial/CMOS/PIT/PIC reuse the same
  handlers as KVM x86.
- Not yet on Windows: **virtio-fs shares** (needs a WinFsp port instead of
  go-fuse) — `-share` fails with a clear error; everything else (blk, net
  vsock, rng, rtc) is platform-neutral Go — the embedded netstack
  gives WHPX networking with no gvproxy-windows.exe either.

Status: cross-compiles, decoder/APIC/PIT unit-tested, **untested on real
Windows yet** (needs Windows 10 1809+ with "Windows Hypervisor Platform"
enabled: `dism /online /enable-feature /featurename:HypervisorPlatform`).

## gVisor-in-guest (defense in depth)

✅ Verified on Apple Silicon: interactive shell, DNS + egress (through
the embedded netstack; netpol applies), `dmesg` shows the sentry's boot
log, `uname` reports its hardcoded `4.19.0-gvisor` impersonation string
(not the real kernel — every syscall is answered by the sentry).

`-runtime runsc` runs the workload container under **gVisor** inside the
VM instead of plain crun:

```
app → gVisor sentry (Go userspace kernel) → guest Linux → gantry VMM → host
```

A container escape then lands in gVisor's small syscall surface rather
than the guest kernel — another wall in front of the device-model trust
boundary. It works because vminitd's runtime path is hardcoded to
`/sbin/crun` and runsc is deliberately runc-CLI-compatible (the same
mechanism containerd shims use); the gVisor rootfs variant just puts
runsc there, real crun kept at `/sbin/crun.runc`:

```
./mkrootfs-gvisor.sh nerdbox-rootfs-arm64.erofs   # → nerdbox-rootfs-gvisor-arm64.erofs
./mkkernel-4k.sh                                   # → nerdbox-kernel-arm64-4k (arm64 only!)
gantry start dev -runtime runsc                    # picks both variants automatically
gantry exec -runtime runsc -- /bin/sh              # one-shot
```

**arm64 needs the 4K kernel**: stock nerdbox arm64 kernels run 16K
pages, and gVisor's release runsc hard-fails in `runsc boot` on a page
size it wasn't compiled for (4K; upstream offers 4K/64K builds, no 16K).
`mkkernel-4k.sh` rebuilds the identical 7.0.12 config with
`CONFIG_ARM64_4K_PAGES=y` — Apple Silicon and KVM both run 4K guests
fine. x86_64 needs nothing (always 4K). The rootfs also installs a tiny
`/sbin/crun` shim (guest/crunshim): it sets up `/dev` (vminitd leaves it
bare and runsc allocates the console pty VM-side), supervises runsc, and
mirrors runsc's logs onto the VM console for debuggability.

Honest limitations: runsc auto-selects its systrap platform in the
guest (no nested /dev/kvm — our VMM doesn't emulate one), so
syscall-heavy workloads are slower than crun; the rootfs grows ~110 MB
(static runsc binary); esoteric
syscalls/devices may be unimplemented in the sentry; networking runs in
--network=host mode (the container shares the VM netns like crun —
isolation stays with the VM + netpol). Concurrent `gantry exec` works
(docker semantics: the second session Execs a process into the same
container). Untested so far: virtio-fs shares through the gofer,
x86_64. crun stays the default. Debug the guest side with
GANTRY_EXTRA_CMDLINE="crunshim.debug=1" (runsc --debug + logs on the VM
console + hang watchdog).

## Network policy

Every sandbox boots with an egress policy enforced on the virtio-net ↔
embedded-netstack link — every guest frame crosses it, so the sandbox
cannot bypass it (works identically on KVM/HVF/WHPX).

**Default posture: internet yes, local network no.** Out of the box the
sandbox can reach the public internet, but not your LAN — RFC1918,
link-local (incl. the `169.254.169.254` cloud metadata endpoint),
loopback, CGNAT, multicast, and the host's own NAT alias are all dropped.
DHCP/DNS via the sandbox's own gateway always work (that's its link, not
the LAN). Relax with `-allow-local-net` or a policy file:

```
gantry start dev -allow-local-net          # internet + LAN
gantry start dev -net-policy policy.json   # custom
```

```json
{
  "default": "deny",
  "allowLocal": false,
  "rules": [
    { "action": "allow", "proto": "tcp", "ports": "443" },
    { "action": "allow", "cidr": "10.9.0.0/16" }
  ],
  "allowDomains": ["deb.debian.org", "*.docker.io"]
}
```

- `default`: `allow` (default) or `deny`; `rules` match in order on
  `cidr` / `proto` (tcp|udp|icmp) / `ports` ("53", "443", "8000-9000")
  BEFORE the local wall, so you can carve out one LAN subnet while the
  rest stays blocked.
- `allowLocal`: master switch for LAN/link-local/host reachability
  (default false).
- `allowDomains`: DNS queries to the gateway resolver are filtered by name
  (wildcards match the bare domain too); answers to allowed names are
  snooped and the resolved IPs allowed for the record TTL (capped 5 min).
  This is how you get "only package registries" sandboxes — see
  `examples/netpol-debian-only.json`.
- Evaluation order: rules → local wall → DNS-learned → default. The wall
  precedes DNS-learned entries on purpose: an allowlisted domain that
  resolves to a local address (DNS rebinding) stays blocked unless local
  access was explicitly granted.
- Caveats, inherent to DNS-based filtering: a guest can still hit
  non-local IPs it already knows without asking DNS — use `default: deny`
  + `rules` for hard guarantees. Policy needs the embedded netstack
  (mutually exclusive with `-gvproxy`).

## Layout vs. the real thing

```
        nerdbox / libsailor (Docker)                gantry
┌───────────────────────────────────┐   ┌───────────────────────────────────┐
│ containerd-shim-nerdbox-v1 (Go)   │   │ main.go — CLI                     │
│ libsailor.so/.dylib (Rust VMM)    │   │ vm_linux.go  — KVM ioctls         │
│  Linux: crates/hypervisor/linux   │   │ vm_darwin.go — Hypervisor.framework│
│  macOS: HVF backend (hv_gic etc.) │   │        via purego (like sailor's) │
│  devices: virtio blk/net/fs/      │   │ virtio.go/vblk/vnet/vvsock/vfs.go │
│  vsock/console/pmem, GICv3, FDT   │   │ virtio-mmio blk/net/vsock/fs, PL011│
│ kernel + erofs rootfs, vminitd    │   │ same kernel + initramfs Go init;  │
│ ttrpc over vsock (dial-back +     │   │ or the REAL nerdbox rootfs via    │
│ listen on 1026)                   │   │ -rootfs (vminitd as PID 1)        │
└───────────────────────────────────┘   └───────────────────────────────────┘
```

Verified against sailor's own decompiled FDT code: same RAM base
(`0x40000000`), same virtio-mmio base (`0x0a000000`), same GIC region.

## Which component is the VMM?

**The `gantry` process itself** — one binary, one process. Everything else
(`hostctl`, `gvproxy`) is just a client or backend talking to it over Unix
sockets.

```
┌─ host ──────────────────────────────────────────────────────────┐
│                                                                 │
│  gantry  ← THE VMM (what libsailor.so/.dylib is for Docker)     │
│  ├─ vm_linux.go / kvm.go       KVM ioctls, GICv3, vCPU run loop │
│  ├─ vm_darwin.go / hv_darwin.go Hypervisor.framework VM+vCPU    │
│  │                              via purego (hv_vm_create, ESR)  │
│  ├─ machine.go / fdt.go        machine model, device tree       │
│  ├─ virtio.go                  virtio-mmio transport core       │
│  │   ├─ vblk.go                disks (ro rootfs + rw rwlayer)   │
│  │   ├─ vnet.go    ──────────► internal/vnet (embedded netstack)│
│  │   ├─ vvsock.go  ◄────────── hostctl (control-plane client)   │
│  │   └─ vfs.go                 virtio-fs → host directories     │
│  └─ uart.go                    PL011 serial console             │
│                                                                 │
│  Inside the guest it created: kernel → vminitd (PID 1) → crun   │
└─────────────────────────────────────────────────────────────────┘
```

| sbx/nerdbox (Docker) | here |
|---|---|
| `libsailor.so/.dylib` — the VMM | **`gantry` binary/process** |
| containerd shim / sbx CLI (control plane) | `hostctl` |
| vpnkit/vfkit (network data plane) | **built into the VMM** (`internal/vnet`, embedded gvisor-tap-vsock) |
| sailor's virtio-fs passthrough server | built into the VMM (`vfs.go`) |

## Run it

```sh
./build.sh

# 1) our guest (static Go init + busybox), KVM host:
./gantry run -kernel ../nerdbox-kernel-arm64_4k -initrd initramfs-shell.cpio.gz

# 2) the REAL nerdbox guest (EROFS rootfs, vminitd), KVM host:
./gantry run -kernel ../nerdbox-kernel-arm64_4k \
             -rootfs ../nerdbox-rootfs-arm64.erofs \
             -vsockfwd /tmp/gantry-vsock
#   vminitd dials back to host port 1025 -> forwarded to /tmp/gantry-vsock/1025.sock
#   host connects to guest's streaming port 1026 via /tmp/gantry-vsock/listen-1026.sock

# 3) on macOS (Apple Silicon): sandbox lifecycle (sbx-style).
#    run-macos.sh builds+signs first; direct binary invocation works too
#    while the hypervisor entitlement is fresh.
./run-macos.sh start dev            # boot a persistent sandbox VM (daemon)
./gantry-darwin-arm64 exec dev      # attach: full Debian bash, writable root
./gantry-darwin-arm64 exec dev -- htop
./gantry-darwin-arm64 ls            # running sandboxes
./run-macos.sh stop dev             # stop; ./run-macos.sh delete dev to remove
# The daemon holds vminitd's single dial-back ttrpc connection and brokers
# concurrent exec sessions over it (like containerd-shim + sbx exec).

# 3b) one-shot: fresh VM + session in a single command, torn down on exit:
./run-macos.sh exec                        # debian + rw rwlayer + bash
./run-macos.sh exec -share code=$HOME/repos,ro -- /bin/sh
# `,ro` is enforced host-side (mutating FUSE opcodes get EROFS), and the
# share is contained: FUSE names with `..`/`/` are rejected and symlinks
# can't lead out of the exported root.

# 3b) same thing, two terminals (debug flow):
#    Terminal 1:
./hostctl-darwin-arm64 shell
#    Terminal 2:
./run-macos.sh container
# This uses the embedded netstack (DHCP/DNS/NAT), attaches virtio-net,
# config.json with bundle.v1, calls task.v3 Create/Start, mounts
# shell-rootfs.erofs from /dev/vdb, and relays stream:// stdio.

# No KVM? QEMU TCG smoke tests (works anywhere):
./run-qemu-test.sh          # scripted guest boot + poweroff
./run-qemu-shell.sh         # interactive busybox shell
./run-qemu-rootfs-test.sh   # boots the real nerdbox EROFS rootfs
```

## gVisor-in-guest (defense in depth)

✅ Verified on Apple Silicon: interactive shell, DNS + egress (through
the embedded netstack; netpol applies), `dmesg` shows the sentry's boot
log, `uname` reports its hardcoded `4.19.0-gvisor` impersonation string
(not the real kernel — every syscall is answered by the sentry).

`-runtime runsc` runs the workload container under **gVisor** inside the
VM instead of plain crun:

```
app → gVisor sentry (Go userspace kernel) → guest Linux → gantry VMM → host
```

A container escape then lands in gVisor's small syscall surface rather
than the guest kernel — another wall in front of the device-model trust
boundary. It works because vminitd's runtime path is hardcoded to
`/sbin/crun` and runsc is deliberately runc-CLI-compatible (the same
mechanism containerd shims use); the gVisor rootfs variant just puts
runsc there, real crun kept at `/sbin/crun.runc`:

```
./mkrootfs-gvisor.sh nerdbox-rootfs-arm64.erofs   # → nerdbox-rootfs-gvisor-arm64.erofs
./mkkernel-4k.sh                                   # → nerdbox-kernel-arm64-4k (arm64 only!)
gantry start dev -runtime runsc                    # picks both variants automatically
gantry exec -runtime runsc -- /bin/sh              # one-shot
```

**arm64 needs the 4K kernel**: stock nerdbox arm64 kernels run 16K
pages, and gVisor's release runsc hard-fails in `runsc boot` on a page
size it wasn't compiled for (4K; upstream offers 4K/64K builds, no 16K).
`mkkernel-4k.sh` rebuilds the identical 7.0.12 config with
`CONFIG_ARM64_4K_PAGES=y` — Apple Silicon and KVM both run 4K guests
fine. x86_64 needs nothing (always 4K). The rootfs also installs a tiny
`/sbin/crun` shim (guest/crunshim): it sets up `/dev` (vminitd leaves it
bare and runsc allocates the console pty VM-side), supervises runsc, and
mirrors runsc's logs onto the VM console for debuggability.

Honest limitations: runsc auto-selects its systrap platform in the
guest (no nested /dev/kvm — our VMM doesn't emulate one), so
syscall-heavy workloads are slower than crun; the rootfs grows ~110 MB
(static runsc binary); esoteric
syscalls/devices may be unimplemented in the sentry; networking runs in
--network=host mode (the container shares the VM netns like crun —
isolation stays with the VM + netpol). Concurrent `gantry exec` works
(docker semantics: the second session Execs a process into the same
container). Untested so far: virtio-fs shares through the gofer,
x86_64. crun stays the default. Debug the guest side with
GANTRY_EXTRA_CMDLINE="crunshim.debug=1" (runsc --debug + logs on the VM
console + hang watchdog).

## Network policy

Every sandbox boots with an egress policy enforced on the virtio-net ↔
embedded-netstack link — every guest frame crosses it, so the sandbox
cannot bypass it (works identically on KVM/HVF/WHPX).

**Default posture: internet yes, local network no.** Out of the box the
sandbox can reach the public internet, but not your LAN — RFC1918,
link-local (incl. the `169.254.169.254` cloud metadata endpoint),
loopback, CGNAT, multicast, and the host's own NAT alias are all dropped.
DHCP/DNS via the sandbox's own gateway always work (that's its link, not
the LAN). Relax with `-allow-local-net` or a policy file:

```
gantry start dev -allow-local-net          # internet + LAN
gantry start dev -net-policy policy.json   # custom
```

```json
{
  "default": "deny",
  "allowLocal": false,
  "rules": [
    { "action": "allow", "proto": "tcp", "ports": "443" },
    { "action": "allow", "cidr": "10.9.0.0/16" }
  ],
  "allowDomains": ["deb.debian.org", "*.docker.io"]
}
```

- `default`: `allow` (default) or `deny`; `rules` match in order on
  `cidr` / `proto` (tcp|udp|icmp) / `ports` ("53", "443", "8000-9000")
  BEFORE the local wall, so you can carve out one LAN subnet while the
  rest stays blocked.
- `allowLocal`: master switch for LAN/link-local/host reachability
  (default false).
- `allowDomains`: DNS queries to the gateway resolver are filtered by name
  (wildcards match the bare domain too); answers to allowed names are
  snooped and the resolved IPs allowed for the record TTL (capped 5 min).
  This is how you get "only package registries" sandboxes — see
  `examples/netpol-debian-only.json`.
- Evaluation order: rules → local wall → DNS-learned → default. The wall
  precedes DNS-learned entries on purpose: an allowlisted domain that
  resolves to a local address (DNS rebinding) stays blocked unless local
  access was explicitly granted.
- Caveats, inherent to DNS-based filtering: a guest can still hit
  non-local IPs it already knows without asking DNS — use `default: deny`
  + `rules` for hard guarantees. Policy needs the embedded netstack
  (mutually exclusive with `-gvproxy`).

## Layout

| package | purpose |
|---|---|
| `internal/virtio/` | the device model and the guest/host trust boundary: virtio-mmio v2 transport + split virtqueues (`virtio.go`), blk (`vblk.go`), net (`vnet.go`), vsock (`vvsock.go`), fs (`vfs.go`, `-share TAG=PATH[,ro]` + shares.json), rng, rtc. Guests are untrusted: queue sizes clamped, descriptor addr/len validated against RAM, FUSE names + symlink containment + host-side `,ro` |
| `internal/vmm/` | machine assembly + boot + hypervisor backends: `machine.go` (RAM, kernel/initrd, devices, `Opts`/`Prepare`/`Run`), `fdt.go`, `bootx86.go` (vmlinux ELF, zero page, MPS), chipset (PL011, 16550, CMOS, PIC/PIT/IO-APIC), `x86emul.go` (WHPX MMIO decode), and the `backend` interface — one `platformBackend()` per target: `vm_linux.go`/`kvm_arm64.go` (KVM arm64), `kvm_amd64.go` (KVM x86-64), `vm_darwin.go`/`hv_darwin.go` (HVF), `whpx_windows.go` (WHPX) |
| `internal/vnet/` | embedded gvisor-tap-vsock netstack (DHCP/DNS/NAT) — no gvproxy binary |
| `internal/netpol/` | egress network policy: ordered L3/L4 rules + DNS-snoop domain allowlist, enforced on the net link |
| `internal/sandbox/` | sandbox lifecycle: start/daemon/exec-attach/ls/stop/delete, the session broker, optional external gvproxy launcher |
| `internal/client/` | shared ttrpc control plane: bundle.v1, task.v3, mount API, stream:// stdio |
| `internal/gutil/` | env helpers (`GANTRY_*`/`MINIVM_*`), cmdline insertion, LE decode |
| root (`main.go`, `exec.go`) | CLI dispatch + one-shot `gantry exec` (VM + net + session) |
| `cmd/hostctl/` | thin two-terminal CLI over internal/client |
| `guest/init/main.go` | guest PID 1 |

Tests are driver-simulation style (no KVM needed) and live next to the
code they cover; `go test -race ./...` is clean.

## Honest gaps

**Threat model.** The device model treats the guest as hostile at the
register/descriptor level (queue sizes clamped, descriptor addresses and
lengths validated against RAM, no host allocation sized by the guest) and
virtio-fs is contained to the exported root (no `..`/`/` in FUSE names, no
symlink escape, `,ro` enforced host-side). What it does NOT give you yet:
per-device I/O sandboxing of the VMM process itself (seccomp/pledge), and
blk/fs device work runs on the vCPU thread, so a slow host filesystem
stalls that vCPU. The VMM process still runs with your full uid privileges.

- no virtio-fs DAX window/pmem, no snapshotting, no CPU throttling (only vCPU count)
- no port publishing yet (vminitd socketforward not wired)
- `hv_gic_*` needs macOS 13+
- KVM ioctls are exercised only through unit tests here (this container's
  cgroup blocks `/dev/kvm`); the QEMU boots validate everything guest-side
- cache maintenance after loading guest images is skipped (fine on modern
  arm64: Graviton/Apple/QEMU-TCG)
