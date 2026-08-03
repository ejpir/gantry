#!/bin/sh
# mkkernel.sh — build Gantry's own hardened guest kernel.
#
# Gantry ships its own kernels (artifacts/gantry-kernel-<arch>[-4k]) rather
# than depending on the stock nerdbox kernel: same version and same baseline
# config lineage (extracted once from the nerdbox kernel, committed under
# config/), minus boot-time dead weight, plus the always-on hardening in
# scripts/kernel-hardening.sh (see docs/sbx-hardening-audit.md for why).
#
#   ./scripts/mkkernel.sh              # → artifacts/gantry-kernel-<host arch>
#   ./scripts/mkkernel.sh x86_64       # cross/native for another arch
#   PAGES=4k ./scripts/mkkernel.sh     # arm64 4K-page variant (runsc)
#                                      # → artifacts/gantry-kernel-arm64-4k
#
# The CLI downloads these exact names from the GitHub release page when
# they are not staged locally, so build once, attach to a release, and
# users never run this script.
#
# Needs: curl, xz, gcc (or CROSS_COMPILE), flex, bison, bc, python3.
# ~10-20 min on a modern machine; incremental afterwards in $WORK.
set -e
STARTPWD=$PWD
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ARTIFACTS=${GANTRY_ARTIFACTS:-$ROOT/artifacts}
mkdir -p "$ARTIFACTS"

VERSION=7.0.12   # must match config/gantry-kernel-*.config lineage
ARCH=${1:-$(uname -m)}
case "$ARCH" in
aarch64|arm64) ARCH=arm64 ;;
amd64|x86_64)  ARCH=x86_64 ;;
*) echo "usage: mkkernel.sh [arm64|x86_64]"; exit 1 ;;
esac
PAGES=${PAGES:-16k}   # arm64 only; x86_64 is always 4K
WORK=${WORK:-/tmp/linux-$VERSION-build-$ARCH}

# Output + make target per arch: arm64 boots the raw Image (ARM\x64 magic),
# x86-64 boots the vmlinux ELF (see bootx86.go). KARCH is the kernel tree's
# arch name; passing it explicitly keeps cross-builds honest (make otherwise
# infers the host arch and would silently build it with the wrong config).
case "$ARCH" in
arm64)
	KARCH=arm64
	if [ "$PAGES" = 4k ]; then
		OUT=${OUT:-$ARTIFACTS/gantry-kernel-arm64-4k}
	else
		OUT=${OUT:-$ARTIFACTS/gantry-kernel-arm64}
	fi
	TARGET=Image
	RESULT=arch/arm64/boot/Image
	;;
x86_64)
	KARCH=x86
	PAGES=4k
	OUT=${OUT:-$ARTIFACTS/gantry-kernel-x86_64}
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
DAX FUSE_DAX                            # virtio-fs runs without the DAX window
DEBUG_MEMORY_INIT                       # kernel-hacking debug option
XEN HYPERV VHOST                        # other hypervisors' guest agents
"
# x86 keeps ACPI (bootx86.go writes RSDP tables) — drop it only on arm64,
# where boot is FDT-only. PCI stays on x86 too: conservative, unmeasured.
if [ "$ARCH" = arm64 ]; then
	DISABLES="$DISABLES
ACPI                                    # boot is FDT-only (3.6 ms probe)
"
fi

# Resolve caller-relative paths before cd $WORK.
abspath() { case "$1" in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$2" "$1" ;; esac }
OUT=$(abspath "$OUT" "$PWD")

. "$ROOT/scripts/kernel-hardening.sh"

if [ ! -d "$WORK" ]; then
	echo "== downloading linux-$VERSION"
	curl -fsSL -o /tmp/linux-$VERSION.tar.xz \
		https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-$VERSION.tar.xz
	echo "== extracting to $WORK"
	mkdir -p "$WORK"
	tar -xJf /tmp/linux-$VERSION.tar.xz -C "$WORK" --strip-components=1
fi

cd "$WORK"
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
# baseline sanity: the guest can't boot without these
if ! grep -q "^CONFIG_EROFS_FS=y" .config || ! grep -q "^CONFIG_VIRTIO_MMIO=y" .config; then
	echo "config baseline failed (.config lacks EROFS_FS/VIRTIO_MMIO)" >&2
	echo "remove $WORK/.config and re-run" >&2
	exit 1
fi

# NOTE: strip the inline comments first — word-splitting DISABLES
# otherwise feeds tokens like "(5.0" to scripts/config, which embeds
# them in grep patterns ("Unmatched ( or \(").
for sym in $(printf '%s\n' "$DISABLES" | sed 's/#.*//'); do
	scripts/config --disable "$sym"
done
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
make ARCH=$KARCH -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" "$TARGET"
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
