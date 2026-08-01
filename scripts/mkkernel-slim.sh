#!/bin/sh
# mkkernel-slim.sh — build a boot-time-optimized nerdbox arm64 guest kernel.
#
# Why: printk gap analysis (see bench-boot.sh notes) showed the stock
# 18 MB kernel spends tens of ms initializing subsystems the guest never
# has: PCI/USB/SCSI (gantry is virtio-mmio only), 9p (gantry shares via
# virtio-fs), KVM (no nested virt in the guest), HugeTLB, ACPI (boot is
# FDT-only). Removing them cut the measured boot phases:
#
#   31.5 ms  console flush        (fixed by loglevel=4 in DefaultCmdline)
#    5.0 ms  HugeTLB
#    3.6 ms  PCI: CLS
#    4.5 ms  PF_INET6 (kept enabled below — see note)
#    ~ms     KVM probe, 9pnet, USB, SCSI, netfilter init
#
# Usage:
#   ./scripts/mkkernel-slim.sh             # → artifacts/nerdbox-kernel-arm64-slim (16K pages)
#   PAGES=4k ./scripts/mkkernel-slim.sh    # 4K-page variant (runsc)
#   ./artifacts/gantry start dev -kernel artifacts/nerdbox-kernel-arm64-slim
#
# Iterate: boot with GANTRY_DEBUG_BOOT=1 and re-run the gap analysis from
# bench-boot.sh; every printk jump >2 ms is a candidate for this list.
set -e
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ARTIFACTS=${GANTRY_ARTIFACTS:-$ROOT/artifacts}
mkdir -p "$ARTIFACTS"

VERSION=7.0.12   # must match mkkernel-4k.sh / the stock kernel
STOCK=${STOCK:-$ARTIFACTS/nerdbox-kernel-arm64}
OUT=${OUT:-$ARTIFACTS/nerdbox-kernel-arm64-slim}
WORK=${WORK:-/tmp/linux-$VERSION-build}
PAGES=${PAGES:-16k}

# Subsystems removed from the stock config. Keep this list conservative:
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
ACPI                                    # boot is FDT-only on both backends
INPUT                                   # no keyboard/mouse; serial console only
DAX FUSE_DAX                            # virtio-fs runs without the DAX window
DEBUG_MEMORY_INIT                       # kernel-hacking debug option
XEN HYPERV VHOST                        # other hypervisors' guest agents
"

# Measured candidates left ENABLED on purpose:
#   INET6      4.5 ms — drop only if you accept IPv4-only guests
#   NF_*              — container port-mapping may want NAT later
#   BPF*              — crun's cgroup-v2 device controller uses eBPF

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
  echo "== extracting config from $STOCK"
  # Not scripts/extract-ikconfig: its GNU-grep regexes fail on macOS's
  # BSD grep ("Unmatched ( or \(") and the truncated .config it leaves
  # behind builds a defconfig kernel that can't mount the erofs rootfs.
  python3 - "$STOCK" > .config <<'PYEOF'
import sys, gzip
data = open(sys.argv[1], 'rb').read()
i, j = data.find(b'IKCFG_ST'), data.find(b'IKCFG_ED')
if i < 0 or j < 0:
    sys.exit('no embedded config (CONFIG_IKCONFIG) in ' + sys.argv[1])
g = data.find(b'\x1f\x8b', i + 8, i + 24)
sys.stdout.buffer.write(gzip.decompress(data[g:j]))
PYEOF
}
# extraction sanity: the guest can't boot without these
if ! grep -q "^CONFIG_EROFS_FS=y" .config || ! grep -q "^CONFIG_VIRTIO_MMIO=y" .config; then
  echo "config extraction failed (.config lacks EROFS_FS/VIRTIO_MMIO)" >&2
  echo "remove $WORK/.config and re-run" >&2
  exit 1
fi

# NOTE: strip the inline comments first — word-splitting DISABLES
# otherwise feeds tokens like "(5.0" to scripts/config, which embeds
# them in grep patterns ("Unmatched ( or \(").
for sym in $(printf '%s\n' "$DISABLES" | sed 's/#.*//'); do
  scripts/config --disable "$sym"
done
case "$PAGES" in
  4k)  scripts/config --disable ARM64_16K_PAGES --disable ARM64_64K_PAGES --enable ARM64_4K_PAGES ;;
  16k) scripts/config --enable ARM64_16K_PAGES ;;
  *)   echo "PAGES must be 4k or 16k" >&2; exit 1 ;;
esac
yes "" | make olddefconfig >/dev/null

echo "== building (this takes a while)"
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" Image
cp arch/arm64/boot/Image "$OUT"
ls -lh "$OUT"

cat <<EOF
done. Measure the difference:

  $ROOT/artifacts/gantry start dev -kernel $OUT
  grep boot-timing ~/.gantry/sandboxes/dev/daemon.log

  # remaining gaps >2 ms:
  GANTRY_DEBUG_BOOT=1 $ROOT/artifacts/gantry start dev -kernel $OUT
  perl -ne 'if (/^\[\s*([0-9.]+)\]\s*(.*)/) { \$t=\$1;
    printf "%6.1f ms  %s\n", (\$t-\$p)*1000, \$pl if defined \$p && (\$t-\$p) > 0.002;
    \$p=\$t; \$pl=\$2 }' ~/.gantry/sandboxes/dev/console.log
EOF
