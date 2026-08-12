#!/bin/bash
set +e
cd /opt/gantry || exit 1
G=./gantry-linux-arm64-kvm-fixed
K=./gantry-kernel-arm64-deferred-smp
R=./nerdbox-rootfs-arm64.erofs
I=./ubuntu-arm64.erofs
PASS=0; FAIL=0
ok(){ echo "PASS: $1"; PASS=$((PASS+1)); }
bad(){ echo "FAIL: $1"; FAIL=$((FAIL+1)); }
printf 'kernel_sha256='; sha256sum "$K"|awk '{print $1}'
printf 'binary_sha256='; sha256sum "$G"|awk '{print $1}'
echo -e 'cpus\trun\trc\tcli_ms\tprep_ms\tready_ms\tboots\tfailures'
for C in 1 2 4 8; do
 for RUN in 1 2 3; do
  N=arm-final-c${C}-r${RUN}; S=/tmp/.gantry/sandboxes/$N
  "$G" stop "$N" >/dev/null 2>&1 || true; rm -rf "$S"
  A=$(date +%s%N)
  GANTRY_BOOT_TIMING=1 timeout 30 "$G" start "$N" -kernel "$K" -rootfs "$R" -image "$I" -cpus "$C" -mem 512 -rw=false -net=false -process-isolation=off >/tmp/$N.start 2>&1
  RC=$?; B=$(date +%s%N); sleep 1
  CLI=$(awk -v n="$((B-A))" 'BEGIN{printf "%.3f",n/1e6}')
  PREP=$(grep -m1 'machine prepared' "$S/daemon.log"|awk '{print $(NF-1)}')
  READY=$(grep -m1 'guest RPC connected (READY)' "$S/daemon.log"|awk '{print $(NF-1)}')
  BOOTS=$(grep -c 'Booted secondary processor' "$S/console.log" 2>/dev/null)
  BAD=$(( $(grep -cE 'failed to online deferred CPU|CPU[0-9]+: failed|psci: failed|Kernel panic' "$S/console.log" 2>/dev/null) + $(grep -cE 'failed to online deferred CPU|PSCI.*fail' "$S/daemon.log" 2>/dev/null) ))
  echo -e "$C\t$RUN\t$RC\t$CLI\t${PREP:-NA}\t${READY:-NA}\t$BOOTS\t$BAD"
  [ "$RC" -eq 0 ] && ok "arm $C-vCPU run $RUN reaches READY" || bad "arm $C-vCPU run $RUN rc=$RC"
  [ "$BOOTS" -eq $((C-1)) ] && ok "arm $C-vCPU run $RUN boots all secondaries" || bad "arm $C-vCPU run $RUN boots=$BOOTS want=$((C-1))"
  [ "$BAD" -eq 0 ] && ok "arm $C-vCPU run $RUN has no CPU failures" || bad "arm $C-vCPU run $RUN failures=$BAD"
  "$G" stop "$N" >/dev/null 2>&1 || true
 done
done
# Verify post-READY workload visibility with networking enabled, because the
# staged old vminitd only creates /etc/hosts while configuring networking.
N=arm-final-online8; S=/tmp/.gantry/sandboxes/$N
"$G" stop "$N" >/dev/null 2>&1 || true; rm -rf "$S"
GANTRY_BOOT_TIMING=1 timeout 30 "$G" start "$N" -kernel "$K" -rootfs "$R" -image "$I" -cpus 8 -mem 512 -rw=false -net=true -process-isolation=off >/tmp/$N.start 2>&1
RC=$?; [ "$RC" -eq 0 ] && ok 'arm network-enabled 8-vCPU reaches READY' || bad "arm network-enabled rc=$RC"
sleep 2
OUT=$(printf 'nproc; grep -c "^processor" /proc/cpuinfo; cat /sys/devices/system/cpu/online; echo AWS-ARM-EXEC-OK\nexit\n' | timeout 90 "$G" exec "$N" 2>&1)
printf '%s\n' "$OUT" | tail -30
COUNT8=$(printf '%s\n' "$OUT" | tr -d '\r' | grep -c '^8$')
[ "$COUNT8" -ge 2 ] && ok 'arm workload observes all 8 CPUs' || bad "arm workload CPU count lines=$COUNT8"
printf '%s\n' "$OUT" | grep -q AWS-ARM-EXEC-OK && ok 'arm guest exec succeeds' || bad 'arm guest exec failed'
"$G" stop "$N" >/dev/null 2>&1 || true
echo "RESULT: $PASS passed, $FAIL failed"; [ "$FAIL" -eq 0 ]
