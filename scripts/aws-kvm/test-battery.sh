#!/bin/bash
# Cross-platform functional battery for Gantry's public VM/CLI surface. AWS
# invokes it through SSM on Linux KVM; the repository-level orchestrator also
# runs it directly on Apple-silicon macOS HVF. All paths and architecture-
# specific assets can be supplied through GANTRY_TEST_* variables.
set +e

BASE=${GANTRY_TEST_ROOT:-/opt/gantry}
cd "$BASE" || exit 1
G=${GANTRY_TEST_EXE:-./gantry-linux-amd64}
KERNEL=${GANTRY_TEST_KERNEL:-$BASE/nerdbox-kernel-x86_64}
ROOTFS=${GANTRY_TEST_ROOTFS:-$BASE/nerdbox-rootfs-x86_64.erofs}
WORKLOAD=${GANTRY_TEST_IMAGE:-$BASE/debian-bookworm-amd64.erofs}
RUNSC_KERNEL=${GANTRY_TEST_RUNSC_KERNEL:-}
RUNSC_ROOTFS=${GANTRY_TEST_RUNSC_ROOTFS:-}
CACHE_IMAGE=${GANTRY_TEST_CACHE_IMAGE:-alpine:latest}
EXPECTED_ARCH=${GANTRY_TEST_EXPECTED_ARCH:-x86_64}
if { [ -n "$RUNSC_KERNEL" ] && [ -z "$RUNSC_ROOTFS" ]; } || \
   { [ -z "$RUNSC_KERNEL" ] && [ -n "$RUNSC_ROOTFS" ]; }; then
  echo "GANTRY_TEST_RUNSC_KERNEL and GANTRY_TEST_RUNSC_ROOTFS must be set together" >&2
  exit 2
fi
# Pin the state roots: under SSM HOME is unset, and layout.Root() /
# image.DefaultStore() otherwise fall back to different directories.
export GANTRY_HOME="${GANTRY_HOME:-/tmp/.gantry/sandboxes}"
export GANTRY_IMAGES="${GANTRY_IMAGES:-/tmp/.gantry/images}"
RWDIR="$(dirname "$GANTRY_HOME")/rwlayers"
PASS=0
FAIL=0
MOCKPID=
MOCKMCP=
HTTP_SESSION=
PORT_SPEC=
EXPORT_ARCHIVE=/tmp/gantry-functional-export-$$.oci.tar
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
chk() { local n="$1" want="$2" got="$3"; if printf '%s' "$got" | grep -qa -- "$want"; then ok "$n"; else bad "$n"; printf '%s\n' "$got" | tail -4; fi; }
# empty_cred asserts the helper emitted NO credential. `gantry exec`
# prints its own client-noise lines, so the test is "no password=" (never
# "no output").
empty_cred() { local n="$1" got="$2"; if printf '%s' "$got" | grep -qa '^password='; then bad "$n"; printf '%s\n' "$got" | tail -3; else ok "$n"; fi; }
run_with_timeout() {
  local seconds=$1
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$seconds" "$@"
  elif command -v perl >/dev/null 2>&1; then
    perl -e 'alarm shift; exec @ARGV' "$seconds" "$@"
  else
    "$@"
  fi
}
xe() { printf '%s\nexit\n' "$2" | run_with_timeout 90 "$G" exec "$1" 2>&1; }
start_runsc() {
  local name=$1
  shift
  set -- "$G" start "$name" -runtime runsc -image "$WORKLOAD" "$@"
  if [ -n "$RUNSC_KERNEL" ]; then
    set -- "$@" -kernel "$RUNSC_KERNEL" -rootfs "$RUNSC_ROOTFS"
  fi
  "$@"
}
new_uuid() { uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid 2>/dev/null || printf fixed; }
file_mode() {
  if [ "$(uname -s)" = Darwin ]; then stat -f %Lp "$1"; else stat -c %a "$1"; fi
}
host_process_contains() {
  local pid=$1 value=$2
  if [ -r "/proc/$pid/environ" ]; then
    { tr '\0' '\n' < "/proc/$pid/environ"; tr '\0' ' ' < "/proc/$pid/cmdline"; } | grep -qs "$value"
  else
    ps eww -p "$pid" -o command= 2>/dev/null | grep -qs "$value"
  fi
}
check_isolation() {
  local path=$1 mode=$2 topology=$3
  shift 3
  python3 - "$path" "$mode" "$topology" "$@" <<'PY'
import json
import sys

path, mode, topology, *roles = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    state = json.load(stream)
if state.get("topology") != topology:
    raise SystemExit(f"topology={state.get('topology')!r}, want {topology!r}")
for role in roles:
    report = state.get(role) or {}
    if not report.get("applied") or report.get("mode") != mode:
        raise SystemExit(f"{role} not applied in {mode} mode: {report}")
for boundary in ("filesystemBoundary", "networkBoundary"):
    if state.get(boundary) != "enforced":
        raise SystemExit(f"{boundary}={state.get(boundary)!r}, want 'enforced'")
PY
}
cleanup() {
  trap - EXIT HUP INT TERM
  [ -z "$PORT_SPEC" ] || "$G" ports unpublish --ephemeral t4 "$PORT_SPEC" >/dev/null 2>&1
  [ -z "$HTTP_SESSION" ] || kill "$HTTP_SESSION" >/dev/null 2>&1
  [ -z "$MOCKPID" ] || kill "$MOCKPID" >/dev/null 2>&1
  [ -z "$MOCKMCP" ] || kill "$MOCKMCP" >/dev/null 2>&1
  for sandbox in t1 t2 t3 t4 t5 t6 t7 t8 t9 t10 t11 t12 t13 t14 t10bad t12bad1 t12bad2; do
    "$G" stop "$sandbox" >/dev/null 2>&1
    "$G" delete "$sandbox" >/dev/null 2>&1
  done
  rm -rf /tmp/sharetest
  rm -f "$EXPORT_ARCHIVE"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

echo "== environment =="
uname -a
[ ! -e /dev/kvm ] || ls -la /dev/kvm

for sandbox in t1 t2 t3 t4 t5 t6 t7 t8 t9 t10 t11 t12 t13 t14 t10bad t12bad1 t12bad2; do
  "$G" stop "$sandbox" >/dev/null 2>&1
  "$G" delete "$sandbox" >/dev/null 2>&1
done
rm -rf "$GANTRY_HOME"/t* "$GANTRY_IMAGES" "$RWDIR"
# rwlayers are per-sandbox defaults now (auto-created, lock-protected, image-paired)

echo "===== crun (t1) ====="
"$G" start t1 -kernel "$KERNEL" -rootfs "$ROOTFS" \
  -image "$WORKLOAD" >/dev/null 2>&1
sleep 1
R=$(xe t1 'uname -m; echo M1');            chk "crun: boot+exec"        "$EXPECTED_ARCH" "$R"
R=$(xe t1 'exit 7');                        chk "crun: exit status"     "status 7" "$R"
R=$(xe t1 'echo SEQ2');                     chk "crun: sequential"      "SEQ2"    "$R"
R=$(xe t1 'if command -v getent >/dev/null; then getent hosts deb.debian.org; else nslookup deb.debian.org; fi')
                                            chk "crun: DNS"             "debian.org" "$R"
R=$(xe t1 'if command -v bash >/dev/null; then timeout 5 bash -c "echo > /dev/tcp/1.1.1.1/443"; else timeout 8 wget -qO /dev/null https://example.com; fi && echo EGRESS-OK')
                                            chk "crun: egress"          "EGRESS-OK" "$R"
R=$(xe t1 'if command -v bash >/dev/null; then timeout 3 bash -c "echo > /dev/tcp/192.168.127.254/80"; else timeout 3 wget -qO /dev/null http://192.168.127.254/; fi && echo WB || echo WALL-OK')
                                            chk "crun: local-net wall"  "WALL-OK" "$R"
( xe t1 'sleep 5; echo CC1-ALIVE' > /tmp/cc1.log 2>&1 ) &
sleep 2
R=$(xe t1 'echo CC2-WORKS');                chk "crun: concurrent (s2)" "CC2-WORKS" "$R"
wait
chk "crun: concurrent (s1)" "CC1-ALIVE" "$(cat /tmp/cc1.log)"
xe t1 'rm -f /session-survivor; (while :; do echo x >> /session-survivor; sleep 0.1; done) &' >/dev/null
R=$(xe t1 'n=$(wc -c < /session-survivor); sleep 2; test "$(wc -c < /session-survivor)" = "$n" && echo TREE-GONE')
                                            chk "crun: session descendants reaped" "TREE-GONE" "$R"

# Exercise revisioned settings persistence on a stopped VM, then verify the
# next boot observes the complete CPU/memory projection.
R=$(xe t1 'printf GANTRY-EXPORT-PERSISTED > /gantry-export-marker && echo MARKER-WRITTEN')
                                            chk "configure/export: writable marker" "MARKER-WRITTEN" "$R"
"$G" stop t1 >/dev/null 2>&1
R=$("$G" configure t1 --cpus=2 --mem=1024 --process-isolation=auto 2>&1)
                                            chk "configure: stopped settings accepted" "updated" "$R"
"$G" resume t1 >/dev/null 2>&1
R=$(xe t1 'n=$(grep -c "^processor" /proc/cpuinfo); m=$(awk "/^MemTotal:/{print \$2}" /proc/meminfo); echo CPUS=$n MEM=$m')
                                            chk "configure: vCPU setting applied" "CPUS=2" "$R"
MEMTOTAL=$(printf '%s\n' "$R" | sed -n 's/.*MEM=\([0-9][0-9]*\).*/\1/p' | tail -1)
[ -n "$MEMTOTAL" ] && [ "$MEMTOTAL" -ge 700000 ] \
  && ok "configure: memory setting applied" || bad "configure: memory setting applied"
if check_isolation "$GANTRY_HOME/t1/isolation.json" auto split-net+split-vmm \
  vmmConfinement networkConfinement; then
  ok "configure: auto confinement roles verified"
else
  bad "configure: auto confinement roles verified"
fi

# A stopped sandbox can be exported, imported through the public image store,
# and booted elsewhere with private-overlay data flattened into its OCI root.
"$G" stop t1 >/dev/null 2>&1
rm -f "$EXPORT_ARCHIVE"
R=$("$G" export --name gantry-e2e/export:latest -o "$EXPORT_ARCHIVE" t1 2>&1)
                                            chk "export: stopped sandbox archived" "gantry export: wrote" "$R"
[ -s "$EXPORT_ARCHIVE" ] && ok "export: archive created" || bad "export: archive created"
[ "$(file_mode "$EXPORT_ARCHIVE" 2>/dev/null)" = 600 ] \
  && ok "export: archive mode is 0600" || bad "export: archive mode is 0600"
R=$("$G" image import --name gantry-e2e/import:latest "$EXPORT_ARCHIVE" 2>&1)
                                            chk "import: OCI archive accepted" "gantry-e2e/import:latest" "$R"
"$G" start t13 -kernel "$KERNEL" -rootfs "$ROOTFS" -image gantry-e2e/import:latest >/dev/null 2>&1
R=$(xe t13 'cat /gantry-export-marker');    chk "import: overlay contents preserved" "GANTRY-EXPORT-PERSISTED" "$R"
"$G" image prune >/dev/null 2>&1
R=$("$G" image ls 2>&1);                   chk "image prune: referenced import preserved" "gantry-e2e/import:latest" "$R"
"$G" stop t13 >/dev/null 2>&1
"$G" delete t13 >/dev/null 2>&1
R=$("$G" image rm gantry-e2e/import:latest 2>&1)
                                            chk "image rm: imported reference removable" "removed" "$R"

echo "===== runsc (t2) ====="
start_runsc t2 >/dev/null 2>&1
sleep 1
R=$(xe t2 'uname -r; cat /proc/1/comm');    chk "runsc: sentry boot"    "4.19.0-gvisor" "$R"
R=$(xe t2 'exit 7');                        chk "runsc: exit status"    "status 7" "$R"
R=$(xe t2 'echo SEQ2');                     chk "runsc: sequential"     "SEQ2"    "$R"
R=$(xe t2 'if command -v getent >/dev/null; then getent hosts deb.debian.org; else nslookup deb.debian.org; fi')
                                            chk "runsc: DNS"            "debian.org" "$R"
R=$(xe t2 'if command -v bash >/dev/null; then timeout 5 bash -c "echo > /dev/tcp/1.1.1.1/443"; else timeout 8 wget -qO /dev/null https://example.com; fi && echo EGRESS-OK')
                                            chk "runsc: egress"         "EGRESS-OK" "$R"
R=$(xe t2 'if command -v bash >/dev/null; then timeout 3 bash -c "echo > /dev/tcp/192.168.127.254/80"; else timeout 3 wget -qO /dev/null http://192.168.127.254/; fi && echo WB || echo WALL-OK')
                                            chk "runsc: local-net wall" "WALL-OK" "$R"
( xe t2 'sleep 5; echo S1-ALIVE' > /tmp/s1.log 2>&1 ) &
sleep 2
R=$(xe t2 'echo S2-WORKS');                 chk "runsc: concurrent (s2)" "S2-WORKS" "$R"
wait
chk "runsc: concurrent (s1)" "S1-ALIVE" "$(cat /tmp/s1.log)"
xe t2 'rm -f /session-survivor; (while :; do echo x >> /session-survivor; sleep 0.1; done) &' >/dev/null
R=$(xe t2 'n=$(wc -c < /session-survivor); sleep 2; test "$(wc -c < /session-survivor)" = "$n" && echo TREE-GONE')
                                            chk "runsc: session descendants reaped" "TREE-GONE" "$R"

echo "===== shares (runsc, t3) ====="
rm -rf /tmp/sharetest && mkdir -p /tmp/sharetest && echo hostfile > /tmp/sharetest/existing.txt
start_runsc t3 -share code=/tmp/sharetest >/dev/null 2>&1
sleep 1
R=$(xe t3 'ls /host/code');                             chk "share: read"   "existing.txt" "$R"
R=$(xe t3 'mkdir /host/code/d2 && echo MK-OK');         chk "share: mkdir"  "MK-OK" "$R"
R=$(xe t3 'echo x > /host/code/f2 && echo WR-OK');      chk "share: write"  "WR-OK" "$R"
[ -f /tmp/sharetest/f2 ] && [ -d /tmp/sharetest/d2 ] && ok "share: visible on host" || bad "share: visible on host"

echo "===== required process isolation (t14) ====="
if "$G" start t14 -process-isolation=required -kernel "$KERNEL" -rootfs "$ROOTFS" \
  -image "$WORKLOAD" >/tmp/t14-start.log 2>&1; then
  if check_isolation "$GANTRY_HOME/t14/isolation.json" required split-net+split-vmm \
    vmmConfinement networkConfinement; then
    ok "isolation: required VMM and network workers verified"
  else
    bad "isolation: required VMM and network workers verified"
  fi
  R=$(xe t14 'echo REQUIRED-VM-ALIVE');     chk "isolation: required VM remains usable" "REQUIRED-VM-ALIVE" "$R"
else
  bad "isolation: required sandbox starts"
  tail -20 /tmp/t14-start.log
fi

echo "===== OCI image (t4: registry/cache resolution) ====="
mkdir -p "$GANTRY_IMAGES"
if [ -n "${GANTRY_STORE_ARCHIVE:-}" ]; then
  tar xzf "$GANTRY_STORE_ARCHIVE" -C "$GANTRY_IMAGES"
elif [ -n "${GANTRY_STORE_URL:-}" ]; then
  # AWS field hosts cannot reach Docker Hub; Resolve must hit this pre-seeded
  # archive offline. Local macOS runs exercise the registry pull path instead.
  for _ in 1 2 3; do curl -fSL --retry 3 -o /tmp/alpine-store.tar.gz "$GANTRY_STORE_URL" && break; sleep 3; done
  tar xzf /tmp/alpine-store.tar.gz -C "$GANTRY_IMAGES"
else
  "$G" image pull "$CACHE_IMAGE"
fi
"$G" image ls
"$G" start t4 -image "$CACHE_IMAGE" 2>&1 | tail -2
sleep 1
R=$(xe t4 'head -1 /etc/os-release');             chk "image: alpine runs"     "Alpine" "$R"
R=$(xe t4 'echo PATH=$PATH');                     chk "image: config env"     "PATH=/usr/local/sbin" "$R"
R=$(xe t4 'busybox | head -1');                   chk "image: busybox links"  "BusyBox" "$R"
R=$("$G" image ls 2>&1);                         chk "image: ls shows cached reference" "$CACHE_IMAGE" "$R"

# Keep one exec session alive as a guest HTTP service while publishing and
# withdrawing a live host port. The chosen loopback port is intentionally
# ephemeral so local developer runs do not need a reserved port.
printf '%s\n' 'mkdir -p /tmp/gantry-http; printf GANTRY-PORT-OK > /tmp/gantry-http/index.html; exec busybox httpd -f -p 18080 -h /tmp/gantry-http' \
  | run_with_timeout 120 "$G" exec t4 >/tmp/gantry-t4-http.log 2>&1 &
HTTP_SESSION=$!
sleep 2
R=$("$G" ports publish --ephemeral t4 18080 2>&1)
                                            chk "ports: ephemeral host allocation accepted" "published" "$R"
PORTS=$("$G" ports ls t4 2>&1)
HOST_PORT=$(printf '%s\n' "$PORTS" | awk '$2 == 18080 { n=split($1, part, ":"); print part[n]; exit }')
if [ -n "$HOST_PORT" ]; then
  ok "ports: allocated host port listed"
else
  bad "ports: allocated host port listed"
fi
PORT_SPEC=$HOST_PORT:18080
PORT_BODY=
for _ in 1 2 3 4 5; do
  PORT_BODY=$(curl -fsS --max-time 2 "http://127.0.0.1:$HOST_PORT/" 2>/dev/null) && break
  sleep 1
done
                                            chk "ports: guest service reachable" "GANTRY-PORT-OK" "$PORT_BODY"
                                            chk "ports: live mapping listed" "$HOST_PORT" "$PORTS"
"$G" ports unpublish --ephemeral t4 "$PORT_SPEC" >/dev/null 2>&1
PORT_SPEC=
if curl -fsS --max-time 1 "http://127.0.0.1:$HOST_PORT/" >/dev/null 2>&1; then
  bad "ports: unpublish closes listener"
else
  ok "ports: unpublish closes listener"
fi
kill "$HTTP_SESSION" >/dev/null 2>&1
wait "$HTTP_SESSION" 2>/dev/null
HTTP_SESSION=

echo "===== secrets (t5: cached OCI image) ====="
# docs/secrets.md acceptance test: a canary value must appear in the
# workload's environment inside the guest and NOWHERE in host state.
CANARY="sk-canary-$(new_uuid)"
FILECANARY="sk-file-$(new_uuid)"
printf '%s\n' "$FILECANARY" > /tmp/canary-file
CANARY="$CANARY" "$G" start t5 -secret CANARY -secret FROM_FILE=@/tmp/canary-file -image "$CACHE_IMAGE" >/dev/null 2>&1
sleep 2
R=$(xe t5 'printenv CANARY');     chk "secrets: env value in guest"   "$CANARY" "$R"
R=$(xe t5 'printenv FROM_FILE');  chk "secrets: @file value in guest" "$FILECANARY" "$R"

grep -q "CANARY" "$GANTRY_HOME"/t5/sandbox.json 2>/dev/null \
  && ok "secrets: name recorded in sandbox.json" || bad "secrets: name recorded in sandbox.json"
grep -q "$CANARY" "$GANTRY_HOME"/t5/sandbox.json 2>/dev/null \
  && bad "secrets: value NOT in sandbox.json" || ok "secrets: value NOT in sandbox.json"

leak=""
grep -rqs "$CANARY" "$GANTRY_HOME"/t5/ && leak="$leak sandbox-dir"
grep -rqs "$CANARY" "$GANTRY_IMAGES"/ 2>/dev/null && leak="$leak image-store"
[ -f "$RWDIR/t5.ext4" ] && grep -qs "$CANARY" "$RWDIR/t5.ext4" && leak="$leak rwlayer"
VPID=$(cat "$GANTRY_HOME"/t5/vmm.pid 2>/dev/null)
[ -n "$VPID" ] && host_process_contains "$VPID" "$CANARY" && leak="$leak process"
[ -z "$leak" ] && ok "secrets: canary absent from host state" || { bad "secrets: canary absent from host state"; echo "  leaked into:$leak"; }

R=$("$G" start t6 -secret TOKEN=literal-value -image "$CACHE_IMAGE" 2>&1)
chk "secrets: literal refused" "refusing" "$R"
# Secret specs validate before any on-disk artifacts: the refused start
# must not leave a fresh per-sandbox rwlayer behind.
[ ! -e "$RWDIR/t6.ext4" ] && ok "resolver: bad spec leaves no rwlayer" || bad "resolver: bad spec leaves no rwlayer"

echo "===== bound secrets + credential helper (t7/t8: cached OCI image) ====="
# docs/credential-brokering.md workstream 1: a NAME@host secret is held
# host-side only, delivered per-use through the vsock broker behind three
# gates (binding → egress → presence), and revocable without a restart.
BOUNDCANARY="sk-bound-$(new_uuid)"
BOUND_TOKEN="$BOUNDCANARY" "$G" start t7 -secret BOUND_TOKEN@git.test -image "$CACHE_IMAGE" >/dev/null 2>&1
sleep 3   # guest-tools delivery races readiness; give the async push a moment

R=$(xe t7 'printenv BOUND_TOKEN || echo ABSENT'); chk "binding: bound secret NOT ambient" "ABSENT" "$R"
R=$(xe t7 'printenv GIT_CONFIG_VALUE_0');         chk "binding: git wired via env config" "/run/gantry/bin/credhelper" "$R"
R=$(xe t7 'test -x /run/gantry/bin/gantry-guest && test -x /run/gantry/bin/credhelper && echo HELPER-OK')
                                                  chk "binding: helper staged in guest" "HELPER-OK" "$R"

QB='printf "protocol=https\nhost=git.test\n\n" | /run/gantry/bin/credhelper get'
QN='printf "protocol=https\nhost=evil.test\n\n" | /run/gantry/bin/credhelper get'
R=$(xe t7 "$QB"); chk "broker: delivers bound credential" "password=$BOUNDCANARY" "$R"
                  chk "broker: git username convention" "username=x-access-token" "$R"
R=$(xe t7 "$QN"); empty_cred "broker: unbound host answers empty" "$R"

grep -q "BOUND_TOKEN@git.test" "$GANTRY_HOME"/t7/sandbox.json 2>/dev/null \
  && ok "binding: name+binding persisted" || bad "binding: name+binding persisted"
grep -q "$BOUNDCANARY" "$GANTRY_HOME"/t7/sandbox.json 2>/dev/null \
  && bad "binding: value NOT in sandbox.json" || ok "binding: value NOT in sandbox.json"

# Mid-session revocation through the control socket (the dashboard op):
# the helper must immediately answer empty — no restart, nothing to scrub
# guest-side, because nothing was ever stored guest-side.
R=$(python3 - "$GANTRY_HOME/t7/ctl.sock" <<'PYEOF'
import json, socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall(b'{"op":"secret.remove","id":"rvk","secret":{"name":"BOUND_TOKEN"}}\n')
sys.stdout.write(s.makefile().readline())
PYEOF
)
chk "revocation: control op accepted" '"ok":true' "$R"
R=$(xe t7 "$QB"); empty_cred "revocation: broker answers empty after remove" "$R"
grep -q "BOUND_TOKEN" "$GANTRY_HOME"/t7/sandbox.json 2>/dev/null \
  && bad "revocation: name dropped from sandbox.json" || ok "revocation: name dropped from sandbox.json"

# Gate 2 (egress): the same binding under a policy whose allowlist
# excludes the host must be denied by the broker even though the value is
# held — a brokered token can never outrun the firewall.
cat > /tmp/netpol-t8.json <<'EOF'
{"default":"deny","allowLocal":true,"allowDomains":["example.com"]}
EOF
BOUND_TOKEN="$BOUNDCANARY" "$G" start t8 -secret BOUND_TOKEN@git.test -net-policy /tmp/netpol-t8.json -image "$CACHE_IMAGE" >/dev/null 2>&1
sleep 3
R=$(xe t8 "$QB"); empty_cred "broker: egress policy denies out-of-allowlist host" "$R"
R=$("$G" net-policy show t8 2>&1);          chk "net policy: persisted allowlist visible" "example.com" "$R"
"$G" net-policy default t8 >/dev/null 2>&1
R=$(xe t8 "$QB");                         chk "net policy: live default restores credential gate" "password=$BOUNDCANARY" "$R"

echo "===== secret sources with TTL (t9: file rotation, fail-closed) ====="
# docs/credential-brokering.md workstream 2: a file-backed bound secret
# resolves at REQUEST time through the daemon's TTL Store — rotating the
# file is picked up without a sandbox restart, and a broken source fails
# closed (empty answer, never a stale value).
echo "file-token-v1" > /tmp/t9-token
"$G" start t9 -secret 'FILE_TOKEN@git.test=@/tmp/t9-token,ttl=2s' -image "$CACHE_IMAGE" >/dev/null 2>&1
sleep 4
QF='printf "protocol=https\nhost=git.test\n\n" | /run/gantry/bin/credhelper get'
R=$(xe t9 "$QF"); chk "source: file value delivered" "password=file-token-v1" "$R"
echo "file-token-v2" > /tmp/t9-token   # rotate on the host
sleep 3                              # past the 2s TTL
R=$(xe t9 "$QF"); chk "source: rotation picked up live" "password=file-token-v2" "$R"
rm -f /tmp/t9-token                  # source breaks after a good resolve
sleep 3
R=$(xe t9 "$QF"); empty_cred "source: fail-closed after source removal" "$R"

echo "===== OAuth custody (t10: mock provider, refresh token held on host) ====="
# Custody depends on the callback bridge and must fail during resolution,
# before creating any sandbox state, when an operator disables that bridge.
R=$("$G" start t10bad -oauth-custody -oauth-bridge=false -image "$CACHE_IMAGE" 2>&1)
chk "custody: disabled callback bridge refused" "requires -oauth-bridge=true" "$R"
[ ! -e "$GANTRY_HOME/t10bad" ] && ok "custody: refused config leaves no sandbox state" || bad "custody: refused config leaves no sandbox state"
# docs/credential-brokering.md workstream 3: with -oauth-custody the guest
# helper runs the PKCE flow but the DAEMON exchanges the code and holds
# the refresh token host-side; the guest auth file carries a short-lived
# access token plus a sentinel. A mock authorization server on the
# instance loopback stands in for the real provider.
cat > /tmp/mock-as.py <<'PYEOF'
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        grant = json.loads(body)
        with open('/tmp/mock-as-grants.log', 'a') as f:
            f.write(grant.get('grant_type', '?') + '\n')
        if grant.get('grant_type') == 'refresh_token':
            tok = {"access_token": "at-mock-REFRESHED", "refresh_token": "rt-mock-1", "expires_in": 3600}
        else:
            # 1s lifetime: with the 5-minute refresh leeway the set is due
            # the moment it lands, exercising the push loop right away.
            tok = {"access_token": "at-mock-1", "refresh_token": "rt-mock-1", "expires_in": 1}
        out = json.dumps(tok).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(out)
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", int(os.environ["MOCK_AS_PORT"])), H).serve_forever()
PYEOF
rm -f /tmp/mock-as-grants.log
MOCK_AS_PORT=$(python3 - <<'PY'
import socket
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
)
MOCK_AS_PORT=$MOCK_AS_PORT python3 /tmp/mock-as.py &
MOCKPID=$!
sleep 1
export GANTRY_OAUTH_TOKEN_URL_CLAUDE=http://127.0.0.1:$MOCK_AS_PORT/token
"$G" start t10 -oauth-custody -image "$CACHE_IMAGE" >/dev/null 2>&1
sleep 4
# The login blocks until the callback lands: run it in the background,
# scrape the authorize URL for its dynamic port + state, and play the
# browser redirect with curl.
( printf '/run/gantry/bin/gantry-guest oauth login claude\nexit\n' | run_with_timeout 60 "$G" exec t10 > /tmp/t10-login.log 2>&1 ) &
sleep 4
URL=$(grep -oa 'https://claude.ai/oauth/authorize[^ ]*' /tmp/t10-login.log | head -1)
CPORT=$(printf '%s' "$URL" | sed -n 's/.*127\.0\.0\.1%3A\([0-9]*\)%2Fcallback.*/\1/p')
CSTATE=$(printf '%s' "$URL" | sed -n 's/.*[?&]state=\([A-Za-z0-9_-]*\).*/\1/p')
curl -s "http://127.0.0.1:$CPORT/callback?code=mock-code&state=$CSTATE" > /tmp/t10-callback.html
# The guest helper polls oauth.status on a ~1s cadence; give the
# completion line time to land in the session log instead of racing it.
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do grep -qa "tokens held on host" /tmp/t10-login.log && break; sleep 1; done
R=$(cat /tmp/t10-callback.html);            chk "custody: callback consumed host-side"        "OAuth callback received" "$R"
R=$(cat /tmp/t10-login.log);                chk "custody: login completed in guest"            "tokens held on host" "$R"
R=$(xe t10 'cat /root/.claude/.credentials.json')
                                            chk "custody: guest holds an access token"        "at-mock-" "$R"
                                            chk "custody: guest refresh token is a sentinel"  "gantry-custody-refresh-held-on-host" "$R"
R=$(cat "$GANTRY_HOME/t10/oauth-tokens.json")
                                            chk "custody: refresh token held host-side"       "rt-mock-1" "$R"
M=$(file_mode "$GANTRY_HOME/t10/oauth-tokens.json")
                                            chk "custody: host token file is 0600"            "^600$" "$M"
sleep 3
R=$(grep custody "$GANTRY_HOME/t10/daemon.log")
                                            chk "custody: refresh loop pushed a fresh token"  "access token refreshed and pushed" "$R"
R=$(xe t10 'cat /root/.claude/.credentials.json')
                                            chk "custody: refreshed token reached the guest"  "at-mock-REFRESHED" "$R"
# Restart durability: the 0600 disk sync lets a resumed daemon re-attach
# the session and its refresh loop.
$G stop t10 >/dev/null 2>&1
$G resume t10 >/dev/null 2>&1
sleep 5
R=$(grep custody "$GANTRY_HOME/t10/daemon.log")
                                            chk "custody: session restored after restart"     "session restored and access token pushed" "$R"
R=$(xe t10 '/run/gantry/bin/gantry-guest oauth login github 2>&1')
                                            chk "custody: unknown provider refused"           "no custody login" "$R"
kill "$MOCKPID" 2>/dev/null
MOCKPID=

echo "===== MCP gateway (t11: fs server via mcp-proxy, containment) ====="
# docs/mcp-gateway.md milestone 1: the agent speaks MCP (NDJSON stdio) to
# gantry-guest mcp-proxy, the host gateway muxes to a contained fs server
# spawned guest-side as an unprivileged user (never root).
"$G" start t11 -mcp -mcp-fs-root /work -mcp-fs-user nobody -image "$CACHE_IMAGE" >/dev/null 2>&1
sleep 4
if check_isolation "$GANTRY_HOME/t11/isolation.json" auto split-net+split-vmm+split-mcp \
  vmmConfinement networkConfinement mcpConfinement; then
  ok "mcp: auto confinement roles verified end to end"
else
  bad "mcp: auto confinement roles verified end to end"
fi
xe t11 'mkdir -p /work/sub && echo hello-mcp > /work/notes.txt && ln -s /etc/passwd /work/evil && chmod 755 /work /work/sub && chmod 644 /work/notes.txt' >/dev/null 2>&1
# The request transcript is built on the instance and heredoc'd into the
# guest — nested JSON quoting through xe is unmaintainable otherwise.
cat > /tmp/t11-reqs.ndjson <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"battery","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fs__read_file","arguments":{"path":"/work/notes.txt"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fs__read_file","arguments":{"path":"/work/evil"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"fs__write_file","arguments":{"path":"/work/x"}}}
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"fs__github-authorize","arguments":{}}}
EOF
{ echo 'cat > /work/.gantry-mcp-requests <<MEOF'; cat /tmp/t11-reqs.ndjson; echo 'MEOF'; echo 'exit'; } | run_with_timeout 90 "$G" exec t11 >/dev/null 2>&1
R=$(printf '{ cat /work/.gantry-mcp-requests; sleep 4; } | /run/gantry/bin/gantry-guest mcp-proxy\nexit\n' | run_with_timeout 60 "$G" exec t11 2>&1)
L2=$(printf '%s' "$R" | grep -a '"id":2');  chk "mcp: tools/list exposes fs__read_file"      "fs__read_file" "$L2"
if printf '%s' "$L2" | grep -qa 'github-authorize'; then bad "mcp: auth tool hidden from listing"; else ok "mcp: auth tool hidden from listing"; fi
L3=$(printf '%s' "$R" | grep -a '"id":3');  chk "mcp: read_file round trip"                 "hello-mcp" "$L3"
L4=$(printf '%s' "$R" | grep -a '"id":4');  chk "mcp: symlink escape is an error"           '"isError":true' "$L4"
if printf '%s' "$L4" | grep -qa 'root:'; then bad "mcp: symlink escape leaked /etc/passwd"; else ok "mcp: symlink escape leaked nothing"; fi
L5=$(printf '%s' "$R" | grep -a '"id":5');  chk "mcp: unlisted tool denied"                 "unknown or disallowed" "$L5"
L6=$(printf '%s' "$R" | grep -a '"id":6');  chk "mcp: authorize tool denied"                "unknown or disallowed" "$L6"
R=$($G audit t11);                          chk "mcp: calls audited host-side"              "mcp: call fs__read_file" "$R"
                                            chk "mcp: denies audited"                      'mcp: denied call "fs__write_file"' "$R"

echo "===== MCP remote upstreams (t12: injection, redaction, SSRF) ====="
# Milestone 2: remote streamable-HTTP upstreams with host-side credential
# injection. The mock remote runs on host loopback — upstream traffic exits
# from the host gateway process, never the guest netns.
cat > /tmp/mock-mcp.py <<'PYEOF'
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
LOG = "/tmp/mock-mcp-auth.log"
TOOLS = [
    {"name": "echo_auth", "description": "echoes Authorization", "inputSchema": {"type": "object"}},
    {"name": "leak", "description": "returns a token-shaped string", "inputSchema": {"type": "object"}},
    {"name": "danger", "description": "policy-denied", "inputSchema": {"type": "object"}},
    {"name": "big", "description": "over-cap response", "inputSchema": {"type": "object"}},
    {"name": "leak_sse", "description": "leaks via SSE framing", "inputSchema": {"type": "object"}},
    {"name": "err_http", "description": "401 reflecting the credential", "inputSchema": {"type": "object"}},
]
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        req = json.loads(self.rfile.read(n) or b"{}")
        with open(LOG, "a") as f:
            f.write((self.headers.get("Authorization") or "<none>") + "\n")
        if "id" not in req:
            self.send_response(202); self.end_headers(); return
        rid, m = req["id"], req.get("method")
        if m == "tools/call" and req.get("params", {}).get("name") == "err_http":
            self.send_response(401)
            self.end_headers()
            self.wfile.write(json.dumps({"detail": "token %s rejected" % (self.headers.get("Authorization") or "")}).encode())
            return
        if m == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "mock-mcp", "version": "0"}}
        elif m == "tools/list":
            result = {"tools": TOOLS}
        elif m == "tools/call":
            name = req.get("params", {}).get("name")
            if name == "echo_auth":
                result = {"content": [{"type": "text", "text": "auth=" + (self.headers.get("Authorization") or "<none>")}]}
            elif name == "leak":
                result = {"content": [{"type": "text", "text": "the token is t12-secret-token"}]}
            elif name == "big":
                result = {"content": [{"type": "text", "text": "A" * (2 * 1024 * 1024)}]}
            elif name == "leak_sse":
                raw = json.dumps({"jsonrpc": "2.0", "id": rid, "result":
                    {"content": [{"type": "text", "text": "sse says t12-secret-token"}]}})
                body = ("event: message\ndata: " + raw + "\n\n").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            else:
                result = {"content": [{"type": "text", "text": "unknown"}], "isError": True}
        else:
            result = {}
        raw = json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
HTTPServer(("127.0.0.1", int(os.environ["MOCK_MCP_PORT"])), H).serve_forever()
PYEOF
rm -f /tmp/mock-mcp-auth.log
MOCK_MCP_PORT=$(python3 - <<'PY'
import socket
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
)
MOCK_MCP_PORT=$MOCK_MCP_PORT python3 /tmp/mock-mcp.py &
MOCKMCP=$!
sleep 1
export T12_MCP_TOKEN=t12-secret-token  # -secret NAME=value is refused (ps/history leak); env-source it
MCP_REMOTE="name=mock,url=http://127.0.0.1:$MOCK_MCP_PORT/mcp,auth=bearer:T12_MCP_TOKEN,allow=*,deny=dang*"
"$G" start t12 -mcp -mcp-fs-root /work -secret T12_MCP_TOKEN \
  -mcp-remote "$MCP_REMOTE" -image "$CACHE_IMAGE" >/dev/null 2>&1
sleep 4
xe t12 'mkdir -p /work && chmod 755 /work' >/dev/null 2>&1  # creates container "sb" the fs server spawns into
cat > /tmp/t12-reqs.ndjson <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"battery","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mock__echo_auth","arguments":{}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"mock__leak","arguments":{}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"mock__danger","arguments":{}}}
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"mock__big","arguments":{}}}
{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"mock__leak_sse","arguments":{}}}
{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"mock__err_http","arguments":{}}}
EOF
{ echo 'cat > /work/.gantry-mcp-requests <<MEOF'; cat /tmp/t12-reqs.ndjson; echo 'MEOF'; echo 'exit'; } | run_with_timeout 90 "$G" exec t12 >/dev/null 2>&1
R=$(printf '{ cat /work/.gantry-mcp-requests; sleep 5; } | /run/gantry/bin/gantry-guest mcp-proxy\nexit\n' | run_with_timeout 60 "$G" exec t12 2>&1)
L2=$(printf '%s' "$R" | grep -a '"id":2');  chk "mcp: remote tools listed alongside fs"         "mock__echo_auth" "$L2"
                                            chk "mcp: fs server still listed"                 "fs__read_file" "$L2"
chk "mcp: injected credential reached the upstream" "Bearer t12-secret-token" "$(cat /tmp/mock-mcp-auth.log 2>/dev/null)"
L3=$(printf '%s' "$R" | grep -a '"id":3');  chk "mcp: reflected credential redacted"         'auth=\*\+' "$L3"
L4=$(printf '%s' "$R" | grep -a '"id":4');  chk "mcp: response-body secret redacted"         'token is \*\+' "$L4"
if printf '%s' "$R" | grep -qa 't12-secret-token'; then bad "mcp: no credential in guest transcript"; else ok "mcp: no credential in guest transcript"; fi
L5=$(printf '%s' "$R" | grep -a '"id":5');  chk "mcp: policy-hidden remote tool denied"       "unknown or disallowed tool" "$L5"
L2b=$(printf '%s' "$R" | grep -a '"id":2'); if printf '%s' "$L2b" | grep -qa 'mock__danger'; then bad "mcp: deny-listed tool hidden from listing"; else ok "mcp: deny-listed tool hidden from listing"; fi
L6=$(printf '%s' "$R" | grep -a '"id":6');  chk "mcp: over-cap response refused"              "upstream call failed" "$L6"
L7=$(printf '%s' "$R" | grep -a '"id":7');  chk "mcp: SSE-framed leak redacted"               'sse says \*\+' "$L7"
L8=$(printf '%s' "$R" | grep -a '"id":8');  chk "mcp: upstream error sanitized to guest"      "upstream call failed" "$L8"
R=$($G audit t12);                          chk "mcp: remote config audited (no values)"     "mcp: remote mock configured" "$R"
                                            chk "mcp: remote calls audited"                 "mcp: call mock__echo_auth" "$R"
                                            chk "mcp: remote policy deny audited"           'mcp: denied call "mock__danger" (policy)' "$R"
                                            chk "mcp: upstream error audited (sanitized)"   "mcp: call mock__err_http upstream error" "$R"
if printf '%s' "$R" | grep -qa 't12-secret-token'; then bad "mcp: audit free of credential values"; else ok "mcp: audit free of credential values"; fi

# t13: operator CLI — config view (names, never values) + live tool probe.
R=$($G mcp t12)
chk "mcp cli: config view shows fs server"        "read-only filesystem: root /work"   "$R"
chk "mcp cli: config view shows remote + auth kind" "auth bearer:T12_MCP_TOKEN"        "$R"
if printf '%s' "$R" | grep -qa 't12-secret-token'; then bad "mcp cli: config view free of values"; else ok "mcp cli: config view free of values"; fi
R=$($G mcp tools t12)
chk "mcp cli: live probe lists fs tools"          "fs: list_directory, read_file"      "$R"
chk "mcp cli: live probe lists remote tools"      "mock: big, echo_auth, err_http, leak, leak_sse" "$R"
if printf '%s' "$R" | grep -qa 'danger'; then bad "mcp cli: probe honors deny policy"; else ok "mcp cli: probe honors deny policy"; fi
# Loud refusals at start time (fail closed, never silent degrade):
OUT=$("$G" start t12bad1 -mcp-remote 'name=evil,url=https://169.254.169.254/latest,allow=*' -image "$CACHE_IMAGE" 2>&1)
chk "mcp: cloud metadata target refused" "non-public" "$OUT"
OUT=$("$G" start t12bad2 -mcp-remote 'name=plain,url=http://1.2.3.4/mcp,allow=*' -image "$CACHE_IMAGE" 2>&1)
chk "mcp: plain HTTP to a public host refused" "plain HTTP" "$OUT"
kill "$MOCKMCP" 2>/dev/null
MOCKMCP=

echo "==============================="
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
