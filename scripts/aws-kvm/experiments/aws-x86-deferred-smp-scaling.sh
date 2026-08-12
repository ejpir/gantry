#!/bin/bash
set +e
cd /opt/gantry || exit 1
G=./gantry-linux-amd64-deferred-smp
K=./gantry-kernel-x86_64
R=./nerdbox-rootfs-x86_64.erofs
I=./debian-bookworm-amd64.erofs
PASS=0
FAIL=0
ok(){ echo "PASS: $1"; PASS=$((PASS+1)); }
bad(){ echo "FAIL: $1"; FAIL=$((FAIL+1)); }
printf 'kernel_sha256='; sha256sum "$K" | awk '{print $1}'
printf 'binary_sha256='; sha256sum "$G" | awk '{print $1}'
printf 'cpus\trc\tcli_ms\tdaemon_ready_ms\tvcpu_ready_ms\tdefer_complete_ms\tonline\n'
for CPUS in 1 2 4 8; do
  NAME=x86-defer-c$CPUS
  STATE=/tmp/.gantry/sandboxes/$NAME
  "$G" stop "$NAME" >/dev/null 2>&1 || true
  rm -rf "$STATE"
  START_NS=$(date +%s%N)
  GANTRY_BOOT_TIMING=1 timeout 60 "$G" start "$NAME" \
    -kernel "$K" -rootfs "$R" -image "$I" -cpus "$CPUS" -mem 512 -rw=false \
    -net=false -process-isolation=off >/tmp/$NAME.start.log 2>&1
  RC=$?
  END_NS=$(date +%s%N)
  CLI=$(awk -v ns="$((END_NS-START_NS))" 'BEGIN{printf "%.3f",ns/1000000}')
  READY=$(grep -m1 'guest RPC connected (READY)' "$STATE/daemon.log" | awk '{print $(NF-1)}')
  VR=$(grep -m1 'guest RPC connected (READY)' "$STATE/daemon.log" | sed -n 's/.*vCPU + \([0-9.]*\) ms.*/\1/p')
  DEFER=$(grep -m1 'gantry: deferred SMP online complete' "$STATE/console.log" | sed -n 's/^\[ *\([0-9.]*\)\].*/\1/p')
  [ -e "$STATE/ctl.sock" ] && CTL=yes || CTL=no
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$CPUS" "$RC" "$CLI" "${READY:-NA}" "${VR:-NA}" "${DEFER:-NA}" "$CTL"
  if [ "$RC" -eq 0 ]; then ok "$CPUS-vCPU owned-kernel guest reaches READY"; else bad "$CPUS-vCPU owned-kernel guest reaches READY rc=$RC"; tail -30 /tmp/$NAME.start.log; fi
  if [ "$CPUS" -gt 1 ]; then
    grep -q 'gantry: deferred SMP online complete' "$STATE/console.log" && ok "$CPUS-vCPU deferred SMP completed" || bad "$CPUS-vCPU deferred SMP completion missing"
  fi
  "$G" stop "$NAME" >/dev/null 2>&1 || true
done
echo 'RESULT LOGS:'
for C in 1 2 4 8; do echo "--- c$C daemon"; grep -E 'boot-timing:|guest first vsock' /tmp/.gantry/sandboxes/x86-defer-c$C/daemon.log; echo "--- c$C console"; grep -E 'gantry: deferred SMP|smpboot:|Brought up|Total of' /tmp/.gantry/sandboxes/x86-defer-c$C/console.log | tail -30; done
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
