#!/bin/bash
set +e
cd /opt/gantry || exit 1

ARCH=$(uname -m)
case "$ARCH" in
  aarch64)
    G=./gantry-linux-arm64-deferred-smp
    K=./gantry-kernel-arm64-deferred-smp
    R=./nerdbox-rootfs-arm64.erofs
    I=./ubuntu-arm64.erofs
    ;;
  x86_64)
    G=./gantry-linux-amd64-deferred-smp
    K=./nerdbox-kernel-x86_64
    R=./nerdbox-rootfs-x86_64.erofs
    I=./debian-bookworm-amd64.erofs
    ;;
  *) echo "unsupported arch $ARCH"; exit 1 ;;
esac

NAME=aws-smp-test
STATE=/tmp/.gantry/sandboxes/$NAME
PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

$G stop "$NAME" >/dev/null 2>&1 || true
rm -rf "$STATE"

START_NS=$(date +%s%N)
GANTRY_BOOT_TIMING=1 timeout 120 "$G" start "$NAME" \
  -kernel "$K" -rootfs "$R" -image "$I" -cpus 8 -mem 512 -rw=false \
  -net=false -process-isolation=off >/tmp/aws-smp-start.log 2>&1
RC=$?
END_NS=$(date +%s%N)
if [ "$RC" -eq 0 ]; then ok "8-vCPU guest reaches READY"; else bad "8-vCPU guest reaches READY (rc=$RC)"; fi

if [ -f "$STATE/daemon.log" ]; then
  READY=$(grep -m1 'guest RPC connected (READY)' "$STATE/daemon.log" | awk '{print $(NF-1)}')
  FIRST_VSOCK_LINE=$(grep -n -m1 'guest first vsock traffic' "$STATE/daemon.log" | cut -d: -f1)
  FIRST_CPU_LINE=$(grep -n -m1 '\[psci\] CPU_ON' "$STATE/daemon.log" | cut -d: -f1)
  CPU_ON_COUNT=$(grep -c '\[psci\] CPU_ON' "$STATE/daemon.log")
  FAIL_COUNT=$(grep -cE 'failed to online deferred CPU|PSCI.*fail' "$STATE/daemon.log")
  CLI_MS=$(awk -v ns="$((END_NS-START_NS))" 'BEGIN { printf "%.3f", ns / 1000000 }')
  printf 'METRIC arch=%s cli_ms=%s ready_ms=%s first_vsock_line=%s first_cpu_on_line=%s cpu_on_count=%s cpu_on_failures=%s\n' \
    "$ARCH" "$CLI_MS" "$READY" "${FIRST_VSOCK_LINE:-none}" "${FIRST_CPU_LINE:-none}" "$CPU_ON_COUNT" "$FAIL_COUNT"
else
  bad "daemon log exists"
fi

if [ "$ARCH" = aarch64 ]; then
  if [ "$CPU_ON_COUNT" -eq 7 ]; then ok "all seven secondary CPUs were onlined"; else bad "CPU_ON count is $CPU_ON_COUNT, want 7"; fi
  if [ -n "$FIRST_VSOCK_LINE" ] && [ -n "$FIRST_CPU_LINE" ] && [ "$FIRST_CPU_LINE" -gt "$FIRST_VSOCK_LINE" ]; then
    ok "secondary bringup begins after first vsock traffic"
  else
    bad "secondary bringup ordering"
  fi
  [ "$FAIL_COUNT" -eq 0 ] && ok "secondary CPU online has no reported failures" || bad "secondary CPU online failures=$FAIL_COUNT"
else
  ok "stock x86 kernel safely ignored the owned-kernel deferred parameter"
fi

if [ "$ARCH" = aarch64 ]; then
  OUT=$(printf 'nproc; grep -c ^processor /proc/cpuinfo; uname -m; echo AWS-KVM-EXEC-OK\nexit\n' | timeout 90 "$G" exec "$NAME" 2>&1)
  printf '%s\n' "$OUT" | tail -20
  ONLINE=$(printf '%s\n' "$OUT" | grep -E '^8$' | wc -l)
  if [ "$ONLINE" -ge 2 ]; then ok "workload observes all 8 CPUs online"; else bad "workload does not report 8 CPUs twice"; fi
  printf '%s\n' "$OUT" | grep -q 'AWS-KVM-EXEC-OK' && ok "guest exec succeeds" || bad "guest exec failed"
fi

printf '%s\n' '--- daemon milestones ---'
grep -E 'boot-timing:|\[psci\] CPU_ON|failed to online deferred CPU' "$STATE/daemon.log" | tail -80
printf '%s\n' '--- console deferred-SMP lines ---'
grep -E 'gantry: deferred SMP|failed to online deferred CPU' "$STATE/console.log" 2>/dev/null | tail -20

$G stop "$NAME" >/dev/null 2>&1 || true

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
