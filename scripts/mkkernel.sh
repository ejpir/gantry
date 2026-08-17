#!/bin/sh
# mkkernel.sh — build Gantry's own hardened guest kernel.
#
# Gantry ships its own kernels (artifacts/gantry-kernel-<arch>[-4k]) rather
# than depending on the stock nerdbox kernel: same version and same baseline
# config lineage (extracted once from the nerdbox kernel, committed under
# config/), minus boot-time dead weight, plus the always-on hardening in
# scripts/kernel-hardening.sh (see docs/hardening-audit.md for why).
#
#   ./scripts/mkkernel.sh              # → artifacts/gantry-kernel-<host arch>
#   ./scripts/mkkernel.sh x86_64       # cross/native for another arch
#   PAGES=4k ./scripts/mkkernel.sh     # arm64 4K-page variant (runsc)
#                                      # → artifacts/gantry-kernel-arm64-4k
#   ERRATA=strip ./scripts/mkkernel.sh arm64   # boot-cost experiment, NOT a
#                                      # release artifact — see ERRATA below
#                                      # → artifacts/gantry-kernel-arm64-noerrata
#   PROBE=idreg ./scripts/mkkernel.sh arm64    # instrumented boot diagnosis,
#                                      # NOT a release artifact — see PROBE
#                                      # → artifacts/gantry-kernel-arm64-probe
#   FIX=none ./scripts/mkkernel.sh arm64       # omit the default arm64 RNDR
#                                      # capability cache for comparison
#                                      # → artifacts/gantry-kernel-arm64-no-rngcap
#   INITCALL_DEBUG=1 ./scripts/mkkernel.sh x86_64
#                                      # retain initcall timestamps in dmesg;
#                                      # diagnostic artifact, not for release
#                                      # → artifacts/gantry-kernel-x86_64-initcall
#
# The CLI downloads these exact names from the GitHub release page when
# they are not staged locally, so build once, attach to a release, and
# users never run this script.
#
# Needs: curl, xz, gcc (or CROSS_COMPILE), flex, bison, bc, python3.
# ~10-20 min on a modern machine. With WORK unset the build uses a fresh
# private temp tree (safe on multi-user machines, but cold every run); for
# incremental builds set WORK to a directory of your own — see below.
set -e
STARTPWD=$PWD
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ARTIFACTS=${GANTRY_ARTIFACTS:-$ROOT/artifacts}
mkdir -p "$ARTIFACTS"

VERSION=7.2     # must match config/gantry-kernel-*.config lineage
# Fail closed on the tarball content: the kernels built here are published
# as release artifacts, so they must come from exactly the audited bytes —
# TLS to cdn.kernel.org is transport security, not content provenance.
# From https://cdn.kernel.org/pub/linux/kernel/v7.x/sha256sums.asc
TAR_SHA256=f9fef3d14c0df53819026f4be74459835c2a0b0dcbf5b5bbd9ea19f0829402b3
ARCH=${1:-$(uname -m)}
case "$ARCH" in
aarch64|arm64) ARCH=arm64 ;;
amd64|x86_64)  ARCH=x86_64 ;;
*) echo "usage: mkkernel.sh [arm64|x86_64]"; exit 1 ;;
esac

# Select the conventional GNU cross prefix when the requested kernel arch
# differs from the build host. Kbuild's ARCH changes source selection only;
# without CROSS_COMPILE it still invokes the host gcc, producing opaque
# target-option errors such as ARM gcc rejecting x86's -m64. An explicit CC
# or CROSS_COMPILE remains authoritative for CI/clang/custom toolchains.
HOST_ARCH=$(uname -m)
case "$HOST_ARCH" in
aarch64|arm64) HOST_ARCH=arm64 ;;
amd64|x86_64)  HOST_ARCH=x86_64 ;;
esac
if [ "$HOST_ARCH" != "$ARCH" ] && [ -z "${CC:-}" ] && [ -z "${CROSS_COMPILE:-}" ]; then
	case "$ARCH" in
	arm64)  CROSS_COMPILE=aarch64-linux-gnu- ;;
	x86_64) CROSS_COMPILE=x86_64-linux-gnu- ;;
	esac
fi
if [ -n "${CROSS_COMPILE:-}" ] && [ -z "${CC:-}" ]; then
	command -v "${CROSS_COMPILE}gcc" >/dev/null 2>&1 || {
		echo "missing cross compiler: ${CROSS_COMPILE}gcc" >&2
		exit 1
	}
	export CROSS_COMPILE
fi
PAGES=${PAGES:-16k}   # arm64 only; x86_64 is always 4K
INITCALL_DEBUG=${INITCALL_DEBUG:-0}
case "$INITCALL_DEBUG" in
0) INITCALL_SUFFIX= ;;
1) INITCALL_SUFFIX=-initcall ;;
*) echo "INITCALL_DEBUG must be 0 or 1" >&2; exit 1 ;;
esac

# ERRATA=strip drops the CPU errata workarounds for third-party arm64 silicon
# (arm64 only). It exists to measure one boot cost: every capability the guest
# kernel evaluates against an ID register does an MRS that Hypervisor.framework
# traps and emulates, and on an M-series host that phase costs ~176 ms before
# the console even comes up (see docs/boot-timing.md).
#
# MEASURED: no improvement (203.8 ms vs 180-183 ms stock, M-series host). The
# errata that were removed match on MIDR_EL1, which HVF serves from VPIDR_EL2
# WITHOUT trapping; the expensive reads are ID_AA64* from feature checks, and
# those remain. Kept only so the experiment can be repeated across kernel
# bumps — it is not a boot-time optimisation.
#
# NOT for release artifacts, which is why the output gets its own name. The
# guest sees the HOST's MIDR, so these workarounds are live whenever the host
# is the affected core — and gantry-kernel-arm64 also boots under KVM on
# Graviton (Neoverse-N1/V1/V2), Ampere, and Raspberry Pi hosts, where several
# of these apply for real. Only under Hypervisor.framework is the host
# guaranteed to be Apple silicon, which no CONFIG_ARM64_ERRATUM_* covers.
ERRATA=${ERRATA:-full}
case "$ERRATA" in
full)  ERRATA_SUFFIX= ;;
strip) ERRATA_SUFFIX=-noerrata ;;
*) echo "ERRATA must be full or strip" >&2; exit 1 ;;
esac
if [ "$ERRATA" = strip ] && [ "$ARCH" != arm64 ]; then
	echo "ERRATA=strip is arm64-only" >&2
	exit 1
fi

# PROBE=idreg instruments the kernel source itself (arm64 only) to count the
# ID-register reads that Hypervisor.framework traps, dump the stack of
# whoever is looping on them, and report the counts at each step of
# mm_core_init. Host-side sampling localised the cost to that function but
# cannot see the call count or the caller — see scripts/kernel-boot-probe.py
# and docs/boot-timing.md. A debugging kernel, never a release artifact.
# PROBE_DUMP_AT sets which read triggers the one-shot dump_stack (default
# 1000): raise it if the trace lands before the interesting loop.
PROBE=${PROBE:-none}
case "$PROBE" in
none)  PROBE_SUFFIX=;      PROBE_ARGS=--skip-probe ;;
idreg) PROBE_SUFFIX=-probe; PROBE_ARGS= ;;
*) echo "PROBE must be none or idreg" >&2; exit 1 ;;
esac

# The standard arm64 kernel applies what the probes found: arm64 answers "does
# this cpu have RNDR?" through this_cpu_has_cap(), which is uncached BY
# DESIGN — it re-reads ID_AA64ISAR0_EL1, and under Hypervisor.framework that
# read traps to EL2 (~0.96 us). SLAB freelist randomisation asks once per slab
# object; every get_random_* during boot asks too. Caching the answer cut boot
# to init from 277 ms to 107 ms on an M-series host, with 141430 reads
# becoming 7. Unlike CONFIG_SLAB_FREELIST_RANDOM=n it keeps the hardening
# kernel-hardening.sh asks for.
#
# Gantry presents homogeneous virtual CPU capabilities, and the cached path is
# used only during early boot before arm64 finalizes its system-wide capability
# alternatives. Promote it to the release default; FIX=none retains a named,
# unpatched comparison build. Independent of PROBE — combine PROBE=idreg with
# either setting to watch the read count collapse or reproduce the baseline.
if [ -z "${FIX+x}" ]; then
	case "$ARCH" in
	arm64)  FIX=rngcap ;;
	x86_64) FIX=none ;;
	esac
fi
case "$FIX" in
none)
	if [ "$ARCH" = arm64 ]; then FIX_SUFFIX=-no-rngcap; else FIX_SUFFIX=; fi
	;;
rngcap) FIX_SUFFIX=; PROBE_ARGS="$PROBE_ARGS --fix-rngcap" ;;
*) echo "FIX must be none or rngcap" >&2; exit 1 ;;
esac
if [ "$PROBE$FIX" != nonenone ] && [ "$ARCH" != arm64 ]; then
	echo "PROBE/FIX are arm64-only" >&2
	exit 1
fi

# Build tree. Never default to a predictable /tmp path: the script cd's
# into WORK and executes its scripts/config and Makefiles, so a shared or
# pre-created directory is cross-user local code execution. (The
# permission scan skips symlinks: their mode is always 777 and conveys
# no access — the target's own entry carries the meaningful bits. A
# kernel tree contains thousands of source symlinks.) Unset WORK →
# fresh private mktemp tree, removed on exit. An explicit WORK is reused
# only after proving it is entirely owned by and writable only by this
# user (a freshly created one is re-validated after mkdir to close the
# creation race).
TEMP_WORK=
ARCHIVE=
cleanup() {
	[ -z "$ARCHIVE" ] || rm -f -- "$ARCHIVE"
	[ -z "$TEMP_WORK" ] || rm -rf -- "$TEMP_WORK"
}
trap cleanup EXIT HUP INT TERM

verify_sha256() { # verify_sha256 <file> <expected-hex> — macOS has shasum, not sha256sum
	if command -v sha256sum >/dev/null 2>&1; then
		[ "$(sha256sum "$1" | cut -d' ' -f1)" = "$2" ]
	else
		[ "$(shasum -a 256 "$1" | cut -d' ' -f1)" = "$2" ]
	fi
}

if [ -z "${WORK+x}" ]; then
	umask 077
	WORK=$(mktemp -d "${TMPDIR:-/tmp}/linux-$VERSION-build-$ARCH.XXXXXX")
	TEMP_WORK=$WORK
else
	[ -e "$WORK" ] || { umask 077; mkdir -p -- "$WORK"; }
	if [ -L "$WORK" ] || [ ! -d "$WORK" ] ||
		[ -n "$(find "$WORK" ! -user "$(id -un)" -print -quit)" ] ||
		[ -n "$(find "$WORK" ! -type l \( -perm -020 -o -perm -002 \) -print -quit)" ]; then
		echo "refusing unsafe WORK directory: $WORK" >&2
		echo "WORK must be a real directory whose contents are all owned by and writable only by $(id -un)" >&2
		exit 1
	fi
fi
# Enforce the same invariant for everything this script CREATES: an
# ambient umask of 0002 (common on CI runners) would leave the tree
# group-writable and a later invocation's validation above would refuse
# its own previous output (the arm64 16k->4k pair shares WORK).
umask 022

# Output + make target per arch: arm64 boots the raw Image (ARM\x64 magic),
# x86-64 boots the vmlinux ELF (see bootx86.go). KARCH is the kernel tree's
# arch name; passing it explicitly keeps cross-builds honest (make otherwise
# infers the host arch and would silently build it with the wrong config).
case "$ARCH" in
arm64)
	KARCH=arm64
	if [ "$PAGES" = 4k ]; then
		OUT=${OUT:-$ARTIFACTS/gantry-kernel-arm64-4k$ERRATA_SUFFIX$FIX_SUFFIX$PROBE_SUFFIX}
	else
		OUT=${OUT:-$ARTIFACTS/gantry-kernel-arm64$ERRATA_SUFFIX$FIX_SUFFIX$PROBE_SUFFIX}
	fi
	TARGET=Image
	RESULT=arch/arm64/boot/Image
	;;
x86_64)
	KARCH=x86
	PAGES=4k
	OUT=${OUT:-$ARTIFACTS/gantry-kernel-x86_64$INITCALL_SUFFIX}
	TARGET=vmlinux
	RESULT=vmlinux
	;;
esac

# Subsystems removed from the baseline config. Keep this list conservative:
# the guest must still run vminitd + crun/runsc + virtio-mmio devices
# (blk, net, fs, vsock, rng, rtc) + erofs/ext4/overlayfs + cgroups/
# namespaces/seccomp/eBPF (container runtime). When in doubt, leave it in.
DISABLES="
HUGETLBFS HUGETLB_PAGE CGROUP_HUGETLB   # no hugepages in guests (5.0 ms)
PCI                                     # virtio-mmio only, no PCI bus (3.6 ms)
NET_9P 9P_FS                            # shares are virtio-fs (FUSE), not 9p
USB                                     # no USB bus
SCSI                                    # disks are virtio-blk
KVM KVM_VFIO                            # no nested virtualization in the guest
INPUT                                   # no keyboard/mouse; serial console only
DAX FS_DAX FUSE_DAX                     # virtio-fs runs without the DAX window
DEBUG_MEMORY_INIT                       # kernel-hacking debug option
XEN HYPERV VHOST                        # other hypervisors' guest agents
"
if [ "$ARCH" = arm64 ]; then
	DISABLES="$DISABLES
ACPI                                    # boot is FDT-only (3.6 ms probe)
"
else
	# Gantry's x86 VMM deliberately boots through a complete MPS table and
	# virtio-mmio, not firmware/PCI. These options initialized nonexistent PC
	# hardware and added about 7 ms to vCPU->READY after the larger KVM CPUID
	# fix. Keep container, network, filesystem, and memory-hardening features.
	DISABLES="$DISABLES
ACPI NUMA X86_MCE                       # no ACPI tables, NUMA nodes, or physical MCE
CPU_FREQ CPU_IDLE                       # fixed virtual CPUs; RAM may use virtio-mem
THERMAL VFIO XFS_FS                     # no sensors, device assignment, or XFS root
BLK_DEV_RAM BLK_DEV_LOOP                # all guest disks are virtio-blk
VIRTIO_PMEM VIRTIO_BALLOON VIRTIO_IOMMU # devices Gantry does not expose
LIBNVDIMM DAX                           # no persistent-memory/DAX data plane
"
fi

# Resolve caller-relative paths before cd $WORK.
abspath() { case "$1" in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$2" "$1" ;; esac }
OUT=$(abspath "$OUT" "$PWD")

. "$ROOT/scripts/kernel-hardening.sh"

if [ ! -f "$WORK/Makefile" ]; then
	echo "== downloading linux-$VERSION"
	# Unpredictable archive path too: a predictable one lets another local
	# user pre-plant a symlink and redirect the download over a user file.
	ARCHIVE=$(mktemp "${TMPDIR:-/tmp}/linux-$VERSION.XXXXXX.tar.xz")
	# kernel.org occasionally resets an HTTP/2 stream on hosted runners
	# (curl exit 92). The archive remains pinned and hash-verified below, so
	# bounded HTTP/1.1 retries improve transport reliability without changing
	# the trusted input.
	curl --http1.1 -fsSL --retry 5 --retry-connrefused --retry-delay 2 \
		--connect-timeout 30 -o "$ARCHIVE" \
		https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-$VERSION.tar.xz
	verify_sha256 "$ARCHIVE" "$TAR_SHA256" || {
		echo "kernel tarball sha256 mismatch (want $TAR_SHA256) — refusing to build" >&2
		exit 1
	}
	echo "== extracting to $WORK"
	tar -xJf "$ARCHIVE" -C "$WORK" --strip-components=1
	rm -f -- "$ARCHIVE"
	ARCHIVE=
fi

cd "$WORK"
# The owned guest and Gantry's virtio-fs device negotiate one bounded reverse
# notification queue. Upstream virtio-fs has no unsolicited device-to-driver
# path, so apply the audited, version-pinned extension after tarball
# verification. Reused WORK trees are accepted only when the exact patch is
# already present.
NOTIFY_PATCH="$ROOT/patches/linux-$VERSION-virtiofs-notifications.patch"
if ! grep -q '^#define VIRTIO_FS_F_NOTIFICATION 23$' include/uapi/linux/virtio_fs.h; then
	patch -p1 < "$NOTIFY_PATCH"
fi
if ! grep -q 'fuse_dev_notify(struct fuse_dev' fs/fuse/dev.c ||
	! grep -q 'virtio_fs_fill_notification_queue' fs/fuse/virtio_fs.c; then
	echo "kernel tree contains an incomplete $NOTIFY_PATCH" >&2
	exit 1
fi
# Linux's adaptive READDIRPLUS heuristic returns to compact READDIR after the
# first page until a later lookup miss asks for PLUS again. Wide tree walkers
# read the parent before descending, so that hint arrives too late and every
# remaining directory needs its own LOOKUP. Continue PLUS only for pages with
# at least one directory per sixteen visible children; file-heavy directories
# retain upstream's compact records. This is independent of reverse notify so
# reused build trees can adopt it without replaying the notification patch.
READDIRPLUS_PATCH="$ROOT/patches/linux-$VERSION-fuse-directory-readdirplus.patch"
if ! grep -q 'gantry_adapt_readdirplus' fs/fuse/readdir.c; then
	patch -p1 < "$READDIRPLUS_PATCH"
fi
if ! grep -q '^#define GANTRY_READDIRPLUS_DIR_RATIO 16$' fs/fuse/readdir.c ||
	! grep -q 'gantry_adapt_readdirplus(file, entries, directories)' fs/fuse/readdir.c; then
	echo "kernel tree contains an incomplete $READDIRPLUS_PATCH" >&2
	exit 1
fi
# Gantry owns both ends of the virtio-fs connection. Negotiate a private
# FUSE_INIT bit and append an explicit marker when a directory response also
# reaches EOF. Stock kernels and servers never negotiate the extension; the
# fallback remains the ordinary zero-length follow-up READDIR.
READDIR_EOF_PATCH="$ROOT/patches/linux-$VERSION-fuse-readdir-eof.patch"
if ! grep -q 'FUSE_GANTRY_READDIR_EOF' include/uapi/linux/fuse.h; then
	patch -p1 < "$READDIR_EOF_PATCH"
fi
if ! grep -q '^#define FUSE_GANTRY_READDIR_EOF[[:space:]]*(1ULL << 63)$' include/uapi/linux/fuse.h ||
	! grep -q 'gantry_readdir_eof' fs/fuse/fuse_i.h ||
	! grep -q 'FUSE_REQUEST_TIMEOUT | FUSE_GANTRY_READDIR_EOF' fs/fuse/inode.c ||
	! grep -q 'fuse_gantry_mark_readdir_eof(file, ctx->pos)' fs/fuse/readdir.c; then
	echo "kernel tree contains an incomplete $READDIR_EOF_PATCH" >&2
	exit 1
fi
# Early userspace performs synchronous RCU operations while mounting its
# filesystems and enabling cgroup controllers. With multiple online CPUs those
# dominate readiness. The owned kernel can boot on CPU 0 and asynchronously
# online the remaining CPUs after PID 1 submits its first vsock packet. Stock
# kernels safely ignore the namespaced opt-in command-line parameter.
SMP_PATCH="$ROOT/patches/linux-$VERSION-deferred-smp.patch"
if ! grep -q 'early_param("gantry.defer_smp"' net/vmw_vsock/virtio_transport.c; then
	patch -p1 < "$SMP_PATCH"
fi
if ! grep -q 'gantry_trigger_deferred_smp' net/vmw_vsock/virtio_transport.c ||
	! grep -q 'gantry: deferred SMP online complete' net/vmw_vsock/virtio_transport.c; then
	echo "kernel tree contains an incomplete $SMP_PATCH" >&2
	exit 1
fi
# After extraction (so the sha256 covers exactly the audited bytes) and
# before configuring, since the probe compiles into the kernel.
RNGCAP_HEADER=arch/arm64/include/asm/archrandom.h
if [ "$ARCH" = arm64 ] && [ "$FIX" = none ] &&
	grep -q 'gantry_cached_has_rng' "$RNGCAP_HEADER"; then
	echo "refusing to label a reused RNDR-patched WORK tree as FIX=none" >&2
	echo "use a fresh WORK directory for the -no-rngcap comparison build" >&2
	exit 1
fi
if [ "$PROBE$FIX" != nonenone ]; then
	# shellcheck disable=SC2086 # PROBE_ARGS is a deliberate word split
	python3 "$ROOT/scripts/kernel-boot-probe.py" "$WORK" \
		--dump-at "${PROBE_DUMP_AT:-1000}" $PROBE_ARGS
fi
if [ "$ARCH" = arm64 ] && [ "$FIX" = rngcap ] &&
	! grep -q 'gantry_cached_has_rng' "$RNGCAP_HEADER"; then
	echo "kernel tree is missing the default arm64 RNDR capability cache" >&2
	exit 1
fi
[ -f .config ] || {
	# Baseline: the committed gantry config. BASE_CONFIG may also point at
	# a stock nerdbox kernel binary to re-extract its embedded config
	# (how the committed baselines are regenerated — see below).
	BASE=$(abspath "${BASE_CONFIG:-$ROOT/config/gantry-kernel-$ARCH.config}" "$STARTPWD")
	if [ -f "$BASE" ] && head -c 4 "$BASE" | grep -q '^#'; then
		echo "== using committed baseline $BASE"
		cp "$BASE" .config
	else
		echo "== extracting config from kernel image $BASE"
		# Not scripts/extract-ikconfig: its GNU-grep regexes fail on
		# macOS's BSD grep and leave a truncated defconfig behind.
		python3 - "$BASE" > .config <<'PYEOF'
import sys, gzip
data = open(sys.argv[1], 'rb').read()
i, j = data.find(b'IKCFG_ST'), data.find(b'IKCFG_ED')
if i < 0 or j < 0:
    sys.exit('no committed baseline config and no embedded config in ' + sys.argv[1])
g = data.find(b'\x1f\x8b', i + 8, i + 24)
sys.stdout.buffer.write(gzip.decompress(data[g:j]))
PYEOF
	fi
}
# Baseline sanity: the guest cannot boot without the filesystem/device pair,
# and deferred SMP requires built-in vsock plus CPU hotplug (a module would
# load too late to parse the early parameter or trigger readiness bringup).
if ! grep -q "^CONFIG_EROFS_FS=y" .config || ! grep -q "^CONFIG_VIRTIO_MMIO=y" .config ||
	! grep -q "^CONFIG_SMP=y" .config || ! grep -q "^CONFIG_HOTPLUG_CPU=y" .config ||
	! grep -q "^CONFIG_VIRTIO_VSOCKETS=y" .config; then
	echo "config baseline failed (.config lacks EROFS/VIRTIO_MMIO or built-in SMP hotplug/vsock)" >&2
	echo "remove $WORK/.config and re-run" >&2
	exit 1
fi

# NOTE: strip the inline comments first — word-splitting DISABLES
# otherwise feeds tokens like "(5.0" to scripts/config, which embeds
# them in grep patterns ("Unmatched ( or \(").
for sym in $(printf '%s\n' "$DISABLES" | sed 's/#.*//'); do
	scripts/config --disable "$sym"
done
if [ "$ARCH" = x86_64 ]; then
	# INPUT and VT default to y unless EXPERT exposes their prompts. Gantry's
	# x86 console is the 8250 serial driver, so neither subsystem is needed.
	# The Windows large-RAM boot path exposes the tail through built-in
	# virtio-mem, which requires hot-remove and contiguous allocation even
	# though Gantry currently only grows memory after boot.
	scripts/config --enable EXPERT --disable INPUT --disable VT --disable VGA_CONSOLE \
		--enable MEMORY_HOTPLUG --enable MEMORY_HOTREMOVE --enable CONTIG_ALLOC \
		--enable VIRTIO_MEM
fi
if [ "$INITCALL_DEBUG" = 1 ]; then
	# Keep printk's normal console level low at runtime and collect these
	# timestamps from dmesg after READY; a verbose serial console would add
	# a VM exit per byte and invalidate the boot phase being measured.
	scripts/config --enable INITCALL_DEBUG
fi
# ERRATA=strip: turn off every errata workaround the baseline enabled, rather
# than a hand-kept list — the set changes with each kernel bump, and a stale
# list would quietly stop stripping what it claims to. The workarounds are
# keyed to specific ARM Ltd, Ampere, Cavium, Rockchip (etc.) cores by MIDR;
# an Apple-silicon host matches none of them. olddefconfig leaves explicitly
# unset symbols alone, so these stay off.
if [ "$ERRATA" = strip ]; then
	stripped=0
	for sym in $(sed -n 's/^CONFIG_\([A-Z0-9_]*ERRATUM[A-Z0-9_]*\)=y$/\1/p' .config); do
		scripts/config --disable "$sym"
		stripped=$((stripped + 1))
	done
	echo "== ERRATA=strip: disabled $stripped CPU errata workarounds (not for release artifacts)"
fi
case "$ARCH/$PAGES" in
arm64/4k)  scripts/config --disable ARM64_16K_PAGES --disable ARM64_64K_PAGES --enable ARM64_4K_PAGES ;;
arm64/16k) scripts/config --enable ARM64_16K_PAGES ;;
x86_64/4k) : ;;
*) echo "PAGES must be 4k or 16k" >&2; exit 1 ;;
esac
apply_kernel_hardening
yes "" | make ARCH=$KARCH olddefconfig >/dev/null
verify_kernel_hardening

echo "== building $ARCH $TARGET ($PAGES pages, hardened)"
# ccache passthrough: CI exports CC/HOSTCC='ccache gcc' and caches the
# small ~/.ccache instead of the multi-GB build tree (which blows the
# 2 GB cache-entry limit on arm64, where two configs build in one tree).
# Values contain a space, so build the argument list with set -- rather
# than a word-split string (which would hand kbuild a bogus 'gcc' target).
set --
[ -n "${CC:-}" ] && set -- "$@" "CC=$CC"
[ -n "${HOSTCC:-}" ] && set -- "$@" "HOSTCC=$HOSTCC"
make ARCH=$KARCH "$@" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" "$TARGET"
cp "$RESULT" "$OUT"
# the artifact must match the requested arch even when cross-building:
# arm64 Image carries "ARM\x64" at 0x38, x86-64 vmlinux is an ELF with
# e_machine 62.
python3 - "$OUT" "$ARCH" <<'PYEOF'
import sys
magic = open(sys.argv[1], 'rb').read(64)
if sys.argv[2] == 'arm64' and magic[56:60] != b'ARM\x64':
    sys.exit(sys.argv[1] + ' is not an arm64 Image (wrong ARCH?)')
if sys.argv[2] == 'x86_64' and not (magic[:4] == b'\x7fELF' and magic[18] == 62):
    sys.exit(sys.argv[1] + ' is not an x86-64 vmlinux ELF (wrong ARCH?)')
PYEOF
ls -lh "$OUT"

# Regenerating the committed baseline after a kernel bump:
#   BASE_CONFIG=artifacts/nerdbox-kernel-$ARCH WORK=/tmp/linux-new ./scripts/mkkernel.sh $ARCH
#   cp /tmp/linux-new/.config config/gantry-kernel-$ARCH.config   # after a boot test
cat <<EOF
done: $OUT
Boot it:
  $ROOT/artifacts/gantry start dev -kernel $OUT
Or stage it as the default (same name → auto-picked, and it is what the
release pipeline publishes):
  cp $OUT $ARTIFACTS/   # already there
EOF
