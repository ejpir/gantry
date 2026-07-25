#!/bin/sh
# Build the VMM, the guest init, and the initramfs.
set -e
cd "$(dirname "$0")"

echo "== build guest init (static arm64)"
(cd guest/init && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o /tmp/gantry-init .)

echo "== build mkinitramfs"
(cd tools/mkinitramfs && go build -o /tmp/mkinitramfs .)

echo "== build initramfs (scripted + interactive variants)"
/tmp/mkinitramfs -out initramfs.cpio.gz init=/tmp/gantry-init bin/busybox=/bin/busybox etc/rc=guest/rc
/tmp/mkinitramfs -out initramfs-shell.cpio.gz init=/tmp/gantry-init bin/busybox=/bin/busybox

echo "== build gantry VMM (host binary)"
go build -o gantry .

echo "done. Run with KVM:  ./gantry run -kernel ../nerdbox-kernel-arm64_4k -initrd initramfs.cpio.gz"
echo "No KVM? Test guest:  ./run-qemu-test.sh"
