#!/bin/bash
# confinement-battery.sh — worker confinement (docs/worker-confinement.md)
# on real x86_64 or ARM64 KVM + AL2023. Runs ON the test instance via ssm.py,
# after the architecture's runner has populated /opt/gantry. AL2023 has no AppArmor
# userns restriction, so the FULL stack is expected: private mount root
# + seccomp filter, all probes enforced. Sandboxes are named c*; the
# stock battery's t* sandboxes are untouched.
set +e
cd /opt/gantry || exit 1

G=${GANTRY_TEST_EXE:-./gantry-linux-amd64}
KERNEL=${GANTRY_TEST_KERNEL:-nerdbox-kernel-x86_64}
ROOTFS=${GANTRY_TEST_ROOTFS:-nerdbox-rootfs-x86_64.erofs}
IMAGE=${GANTRY_TEST_IMAGE:-debian-bookworm-amd64.erofs}
EXPECTED_ARCH=${GANTRY_TEST_ARCH:-x86_64}
# SSM does not consistently provide HOME. Pin the same state root Gantry uses
# so evidence checks never inspect /tmp/.gantry while the daemon selected its
# separate no-home fallback.
export GANTRY_HOME="${GANTRY_HOME:-/tmp/.gantry/sandboxes}"
export GANTRY_IMAGES="${GANTRY_IMAGES:-/tmp/.gantry/images}"
SBX=$GANTRY_HOME
PASS=0; FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
chk() { local n="$1" want="$2" got="$3"; if printf '%s' "$got" | grep -qa -- "$want"; then ok "$n"; else bad "$n"; printf '%s\n' "$got" | tail -4; fi; }
role_prop() {
  python3 - "$1" "$2" "$3" <<'PY' 2>/dev/null
import json, sys
path, role, prop = sys.argv[1:]
with open(path, encoding="utf-8") as source:
    report = json.load(source).get(role) or {}
for result in report.get("properties", []):
    if result.get("name") == prop:
        print(result.get("state", "missing"))
        break
else:
    print("missing")
PY
}
xe() { printf '%s\nexit\n' "$2" | timeout 90 $G exec "$1" 2>&1; }

echo "== environment =="
uname -a
ls -la /dev/kvm || echo "NO /dev/kvm!"
$G stop c1 >/dev/null 2>&1; $G stop c2 >/dev/null 2>&1; $G stop c3 >/dev/null 2>&1
rm -rf "$SBX"/c1 "$SBX"/c2 "$SBX"/c3

echo "===== c1: -process-isolation=required under real KVM ====="
$G start c1 -process-isolation=required -kernel "$KERNEL" \
  -rootfs "$ROOTFS" -image "$IMAGE" 2>&1 | tail -2
sleep 1

ISO=""
for _ in 1 2 3 4 5 6 7 8 9 10; do ISO=$(tr -d ' \n' < "$SBX"/c1/isolation.json 2>/dev/null); [ -n "$ISO" ] && break; sleep 0.5; done
chk "required: isolation.json exists"      "topology"                 "$ISO"
chk "required: split-net+split-vmm"        "split-net+split-vmm"      "$ISO"
chk "required: confinement applied"        '"applied":true'           "$ISO"
chk "required: mode required"              '"mode":"required"'        "$ISO"
chk "required: all boundaries enforced"    '"filesystemBoundary":"enforced"' "$ISO"
chk "required: network boundary enforced"  '"networkBoundary":"enforced"'    "$ISO"
chk "required: process boundary enforced"  '"processBoundary":"enforced"'    "$ISO"
# enforced is the only acceptable probe verdict under required
if printf '%s' "$ISO" | grep -qa '"state":"unenforced"'; then bad "required: no unenforced probes"; else ok "required: no unenforced probes"; fi
[ "$(role_prop "$SBX/c1/isolation.json" vmmConfinement landlock)" = enforced ] && ok "required: VMM Landlock enforced" || bad "required: VMM Landlock enforced"
[ "$(role_prop "$SBX/c1/isolation.json" networkConfinement landlock)" = enforced ] && ok "required: network Landlock enforced" || bad "required: network Landlock enforced"

R=$(xe c1 'uname -m; echo M1');           chk "required: boot+exec"   "$EXPECTED_ARCH"  "$R"
R=$(xe c1 'timeout 5 bash -c "echo > /dev/tcp/1.1.1.1/443" && echo EGRESS-OK')
                                          chk "required: egress"      "EGRESS-OK" "$R"

echo "----- worker process evidence -----"
DPID=$(cat "$SBX"/c1/vmm.pid 2>/dev/null)
WPID=$(pgrep -P "$DPID" -f '_vmm-worker' 2>/dev/null | head -1)
if [ -z "$WPID" ]; then bad "worker: c1 _vmm-worker running"; else
  ok "worker: _vmm-worker running (pid $WPID)"
  SC=$(awk '/^Seccomp:/{print $2}' /proc/$WPID/status 2>/dev/null)
  [ "$SC" = "2" ] && ok "worker: seccomp filter active (Seccomp: 2)" || bad "worker: seccomp filter active (Seccomp: $SC)"
  NF=$(awk '/^Seccomp_filters:/{print $2}' /proc/$WPID/status 2>/dev/null)
  [ "${NF:-0}" -ge 1 ] && ok "worker: $NF seccomp filter(s) installed" || bad "worker: seccomp filters installed"
  # private mount root: the worker's / must NOT see the host /etc
  WETC=$(ls /proc/$WPID/root/etc 2>/dev/null | wc -l)
  [ "$WETC" = "0" ] && ok "worker: private root (empty /etc)" || bad "worker: private root (/etc has $WETC entries)"
  # the worker holds no open path fds outside its fd table: /dev/kvm
  # open + no cwd path (cwd should be the private root or deleted)
  ls -l /proc/$WPID/cwd 2>/dev/null | tail -1
fi

echo "===== c2: auto mode + confined share hot-add (linux keeps it) ====="
mkdir -p /tmp/hottest && echo hotcontent > /tmp/hottest/hot.txt
$G start c2 -process-isolation=auto -kernel "$KERNEL" \
  -rootfs "$ROOTFS" -image "$IMAGE" \
  -share boot=/tmp/hottest,ro >/dev/null 2>&1
sleep 1
ISO2=""
for _ in 1 2 3 4 5 6 7 8 9 10; do ISO2=$(tr -d ' \n' < "$SBX"/c2/isolation.json 2>/dev/null); [ -n "$ISO2" ] && break; sleep 0.5; done
chk "auto: confinement applied"           '"applied":true'            "$ISO2"
R=$(xe c2 'cat /host/boot/hot.txt');      chk "auto: boot share read" "hotcontent" "$R"
R=$(xe c2 'echo x > /host/boot/evil 2>/dev/null && echo RO-BROKEN || echo RO-WALLED')
                                          chk "auto: ro share walled" "RO-WALLED" "$R"

# LIVE hot-add under confinement — shares stay in the supervisor and reach the
# VMM over the existing broker/vhost relay, so neither Linux Landlock nor the
# immutable Darwin Seatbelt profile needs a new host-path allowance.
# Also exercises the hub root-mtime invalidation: the tag must be
# visible WITHOUT a remount.
mkdir -p /tmp/hottest2 && echo liveadd > /tmp/hottest2/live.txt
$G share add c2 live=/tmp/hottest2 2>&1 | tail -1
R=""
for _ in 1 2 3 4 5 6; do R=$(xe c2 'ls /host/'); printf '%s' "$R" | grep -qa "live" && break; sleep 1; done
chk "auto: hot-added tag visible live"    "live"   "$R"
R=$(xe c2 'cat /host/live/live.txt')
chk "auto: hot-added share serves"        "liveadd" "$R"
R=$(xe c2 'echo w > /host/live/w.txt && echo WR-OK')
chk "auto: hot-added rw write"            "WR-OK"  "$R"
[ -f /tmp/hottest2/w.txt ] && ok "auto: write visible on host" || bad "auto: write visible on host"
R=$(xe c2 'sync -f /host/live && echo SYNCFS-OK')
chk "auto: share syncfs succeeds"          "SYNCFS-OK" "$R"
if grep -Rqa 'Unimplemented opcode SYNCFS' "$SBX/c2"/*.log 2>/dev/null; then
  bad "auto: SYNCFS opcode implemented"
else
  ok "auto: SYNCFS opcode implemented"
fi

echo "----- worker-vmm.log postmortem captured -----"
[ -s "$SBX"/c1/worker-vmm.log ] && ok "postmortem: worker-vmm.log nonempty" || { bad "postmortem: worker-vmm.log nonempty"; ls -la "$SBX"/c1/; }

echo "===== c3: required MCP worker + Landlock + nonfatal worker death ====="
$G start c3 -process-isolation=required -mcp -mcp-fs-root /work -mcp-fs-user nobody \
  -kernel "$KERNEL" -rootfs "$ROOTFS" \
  -image "$IMAGE" >/tmp/c3-start.log 2>&1
C3START=$?
[ "$C3START" = 0 ] && ok "mcp required: sandbox started" || { bad "mcp required: sandbox started"; tail -20 /tmp/c3-start.log; }
sleep 2
ISO3=$(tr -d ' \n' < "$SBX"/c3/isolation.json 2>/dev/null)
chk "mcp required: split topology" "split-net+split-vmm+split-mcp" "$ISO3"
chk "mcp required: report persisted" '"mcpConfinement"' "$ISO3"
chk "mcp required: brokers reported" '"originDialBrokered":true' "$ISO3"
[ "$(role_prop "$SBX/c3/isolation.json" mcpConfinement landlock)" = enforced ] && ok "mcp required: Landlock enforced" || bad "mcp required: Landlock enforced"

D3PID=$(cat "$SBX"/c3/vmm.pid 2>/dev/null)
MCP_PID=$(pgrep -P "$D3PID" -f '_mcp-worker' 2>/dev/null | head -1)
if [ -z "$MCP_PID" ]; then bad "mcp worker: child process running"; else
  ok "mcp worker: child process running (pid $MCP_PID)"
  SC=$(awk '/^Seccomp:/{print $2}' /proc/$MCP_PID/status 2>/dev/null)
  [ "$SC" = "2" ] && ok "mcp worker: seccomp active" || bad "mcp worker: seccomp active (Seccomp: $SC)"
  WETC=$(ls /proc/$MCP_PID/root/etc 2>/dev/null | wc -l)
  [ "$WETC" = "0" ] && ok "mcp worker: private root" || bad "mcp worker: private root (/etc has $WETC entries)"
fi

# MCP readiness now includes verified guest-helper delivery. A bounded probe
# proves the helper and opaque supervisor relay both remain functional after
# all in-worker controls land.
for _ in 1 2 3 4 5 6 7 8 9 10; do
  R=$(xe c3 'test -x /run/gantry/bin/gantry-guest && echo READY')
  printf '%s' "$R" | grep -qa READY && break
  sleep 1
done
R=$(xe c3 'mkdir -p /work; chmod 755 /work; printf "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\\n" | timeout 20 /run/gantry/bin/gantry-guest mcp-proxy')
chk "mcp required: confined relay functional" "fs__read_file" "$R"

if [ -n "$MCP_PID" ]; then kill -9 "$MCP_PID" 2>/dev/null; fi
sleep 2
R=$(xe c3 'echo VM-STILL-ALIVE')
chk "mcp death: ordinary exec survives" "VM-STILL-ALIVE" "$R"
ISO3DEAD=$(tr -d ' \n' < "$SBX"/c3/isolation.json 2>/dev/null)
if printf '%s' "$ISO3DEAD" | grep -qa 'split-mcp'; then bad "mcp death: effective topology withdrawn"; else ok "mcp death: effective topology withdrawn"; fi
chk "mcp death: degradation recorded" "mcpworkerconfinementreportunavailable" "$(printf '%s' "$ISO3DEAD" | tr -d ' -')"

echo "==============================="
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
