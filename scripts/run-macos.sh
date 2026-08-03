#!/bin/sh
# Run gantry on macOS (Apple Silicon) under Hypervisor.framework.
#
#   ./scripts/run-macos.sh            # our guest init + busybox shell (interactive)
#   ./scripts/run-macos.sh rootfs     # the real nerdbox rootfs + vminitd
#   ./scripts/run-macos.sh container  # two-terminal hostctl debug (external gvproxy)
#   ./scripts/run-macos.sh exec ...   # one-shot: build+sign, then `gantry exec`
#
# Requirements: macOS 13+ (hv_gic_* APIs), Apple Silicon.
# The binary needs the hypervisor entitlement; we ad-hoc codesign locally.
set -e

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ARTIFACTS=${GANTRY_ARTIFACTS:-$ROOT/artifacts}
mkdir -p "$ARTIFACTS"

BIN="${GANTRY_BIN:-$ARTIFACTS/gantry-darwin-arm64}"
KERNEL="${KERNEL:-$ARTIFACTS/nerdbox-kernel-arm64}"   # 16K pages — the macOS build
ROOTFS="$ARTIFACTS/nerdbox-rootfs-arm64.erofs"
INITRD="$ARTIFACTS/initramfs-shell.cpio.gz"
HOSTCTL="$ARTIFACTS/hostctl-darwin-arm64"
cd "$ROOT"

# 1. build if Go is available, else use the prebuilt binary from artifacts/
if command -v go >/dev/null 2>&1; then
  echo "== building $BIN"
  (cd "$ROOT" && GOOS=darwin GOARCH=arm64 go build -o "$BIN" ./cmd/gantry)
fi
[ -x "$BIN" ] || { echo "no $BIN and no Go toolchain"; exit 1; }

# 2. ad-hoc codesign with the hypervisor entitlement (idempotent)
echo "== codesign (ad-hoc) with com.apple.security.hypervisor"
codesign --sign - --entitlements "$ROOT/config/entitlements.plist" -f "$BIN" 2>&1 | grep -v 'replacing existing signature' || true

# 3. run
case "$1" in
  rootfs)
    mkdir -p /tmp/gantry-vsock
    if [ ! -S /tmp/gantry-vsock/1025.sock ]; then
      echo "tip: run '$HOSTCTL shell' in another terminal first"
      echo "     (vminitd dials back to the host ~0.5s into boot)"
    fi
    exec "$BIN" run -kernel "$KERNEL" \
      -rootfs "$ROOTFS" \
      -vsockfwd /tmp/gantry-vsock
    ;;
  rootfs-shell)
    # debug-only: initramfs shell, real nerdbox rootfs mounted at /mnt
    exec "$BIN" run -kernel "$KERNEL" \
      -initrd "$INITRD" \
      -rootfs "$ROOTFS"
    ;;
  container)
    # The real path: vminitd + task.v3 + crun, with the container rootfs
    # attached as /dev/vdb. Start `hostctl shell` first.
    # IMAGE picks the container rootfs (default: busybox; a Debian EROFS
    # gives a full Debian userland). RWLAYER attaches an ext4 rwlayer as
    # /dev/vdc for a writable overlay root (hostctl --rw).
    IMAGE="${IMAGE:-$ARTIFACTS/shell-rootfs.erofs}"
    mkdir -p /tmp/gantry-vsock
    if [ ! -S /tmp/gantry-vsock/1025.sock ]; then
      echo "start this first in another terminal:"
      hint="$HOSTCTL shell"
      [ -n "${GANTRY_SHARE:-${MINIVM_SHARE:-}}${GANTRY_SHARES:-${MINIVM_SHARES:-}}" ] && hint="$hint --share"
      [ -n "${RWLAYER:-}" ] && hint="$hint --rw"
      [ "$IMAGE" != "$ARTIFACTS/shell-rootfs.erofs" ] && hint="$hint -- /bin/bash"
      echo "  $hint"
      echo
    fi

    # Match nerdbox/libkrun's documented macOS network path: a virtio-net
    # device exchanges raw Ethernet datagrams with gvproxy's vfkit endpoint.
    GVPROXY="$ARTIFACTS/gvproxy-darwin-arm64"
    [ -x "$GVPROXY" ] || { echo "missing $GVPROXY"; exit 1; }
    codesign --sign - -f "$GVPROXY" 2>&1 | grep -v 'replacing existing signature' || true
    NET_SOCK=/tmp/gantry-net.sock
    NET_API=/tmp/gantry-gvproxy-api.sock
    NET_LOG=/tmp/gantry-gvproxy.log
    rm -f "$NET_SOCK" "$NET_SOCK.client" "$NET_API"
    # gvproxy's SSH-forward listener defaults to tcp/2222 and collides
    # across instances (and with podman's gvproxy); give it a random one.
    "$GVPROXY" -debug -ssh-port $((20000 + RANDOM % 20000)) \
      -listen "unix://$NET_API" \
      -listen-vfkit "unixgram://$NET_SOCK" >"$NET_LOG" 2>&1 &
    GVPROXY_PID=$!
    cleanup_net() {
      kill "$GVPROXY_PID" 2>/dev/null || true
      wait "$GVPROXY_PID" 2>/dev/null || true
      rm -f "$NET_SOCK" "$NET_SOCK.client" "$NET_API"
    }
    trap cleanup_net EXIT HUP INT TERM
    i=0
    while [ ! -S "$NET_SOCK" ] && [ "$i" -lt 100 ]; do
      if ! kill -0 "$GVPROXY_PID" 2>/dev/null; then
        echo "gvproxy exited; see $NET_LOG"
        exit 1
      fi
      sleep 0.05
      i=$((i + 1))
    done
    [ -S "$NET_SOCK" ] || { echo "gvproxy did not create $NET_SOCK; see $NET_LOG"; exit 1; }
    echo "== gvproxy network ready ($NET_SOCK)"

    echo "== container rootfs: $IMAGE -> /dev/vdb"
    set -- "$BIN" run -kernel "$KERNEL" \
      -rootfs "$ROOTFS" \
      -disk "$IMAGE" \
      -net "$NET_SOCK" \
      -vsockfwd /tmp/gantry-vsock
    if [ -n "${RWLAYER:-}" ]; then
      echo "== writable layer: $RWLAYER -> /dev/vdc (use: hostctl shell --rw)"
      set -- "$@" -disk "$RWLAYER"
    fi
    if [ -n "${GANTRY_SHARE:-${MINIVM_SHARE:-}}" ]; then
      echo "== virtio-fs host share: ${GANTRY_SHARE:-$MINIVM_SHARE} -> container /host"
      set -- "$@" -share "hostshare=${GANTRY_SHARE:-$MINIVM_SHARE}"
    fi
    # Extra shares (space-separated TAG=PATH[,ro]; no spaces in paths):
    #   GANTRY_SHARES="code=/Users/you/repos,ro docs=/Users/you/Documents"
    # land at /host/<tag> inside the container.
    if [ -n "${GANTRY_SHARES:-${MINIVM_SHARES:-}}" ]; then
      echo "== virtio-fs extra shares: ${GANTRY_SHARES:-$MINIVM_SHARES} -> container /host/<tag>"
      for spec in ${GANTRY_SHARES:-$MINIVM_SHARES}; do set -- "$@" -share "$spec"; done
    fi
    "$@"
    ;;
  exec)
    shift
    exec "$BIN" exec "$@"
    ;;
  start|stop|ls|delete)
    exec "$BIN" "$@"
    ;;
  *)
    exec "$BIN" run -kernel "$KERNEL" -initrd "$INITRD"
    ;;
esac
