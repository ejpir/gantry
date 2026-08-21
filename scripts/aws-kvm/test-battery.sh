#!/bin/bash
# test-battery.sh — the gantry x86_64 test suite. Runs ON the test
# instance (via ssm.py / run-tests.sh). Expects /opt/gantry populated;
# if GANTRY_ASSET_URL is set, (re)downloads the gantry binary first —
# NOTE: the sandbox daemons hold the ttrpc client, so sandboxes are
# always restarted after a binary swap (this script stops them).
set +e
cd /opt/gantry || exit 1

G=./gantry-linux-amd64
# Pin the state roots: under SSM HOME is unset, and layout.Root() /
# image.DefaultStore() fall back to DIFFERENT directories (/tmp/gantry-0
# vs /tmp/.gantry), which would make every sandbox.json/ctl.sock check
# below silently probe the wrong tree.
export GANTRY_HOME="${GANTRY_HOME:-/tmp/.gantry/sandboxes}"
export GANTRY_IMAGES="${GANTRY_IMAGES:-/tmp/.gantry/images}"
RWDIR="$(dirname "$GANTRY_HOME")/rwlayers"
KERNEL=${GANTRY_TEST_KERNEL:-nerdbox-kernel-x86_64}
PASS=0; FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
chk() { local n="$1" want="$2" got="$3"; if printf '%s' "$got" | grep -qa -- "$want"; then ok "$n"; else bad "$n"; printf '%s\n' "$got" | tail -4; fi; }
# empty_cred asserts the helper emitted NO credential. `gantry exec`
# prints its own client-noise lines, so the test is "no password=" (never
# "no output").
empty_cred() { local n="$1" got="$2"; if printf '%s' "$got" | grep -qa '^password='; then bad "$n"; printf '%s\n' "$got" | tail -3; else ok "$n"; fi; }
xe() { printf '%s\nexit\n' "$2" | timeout 90 $G exec "$1" 2>&1; }

echo "== environment =="
uname -m; ls -la /dev/kvm || echo "NO /dev/kvm!"

for s in t1 t2 t3 t4; do $G stop "$s" >/dev/null 2>&1; done
rm -rf "$GANTRY_HOME"/t* "$GANTRY_IMAGES" "$RWDIR"
# rwlayers are per-sandbox defaults now (auto-created, flock'd, image-paired)

echo "===== crun (t1) ====="
$G start t1 -kernel "$KERNEL" -rootfs nerdbox-rootfs-x86_64.erofs \
  -image debian-bookworm-amd64.erofs >/dev/null 2>&1
sleep 1
R=$(xe t1 'uname -m; echo M1');            chk "crun: boot+exec"        "x86_64"  "$R"
R=$(xe t1 'exit 7');                        chk "crun: exit status"     "status 7" "$R"
R=$(xe t1 'echo SEQ2');                     chk "crun: sequential"      "SEQ2"    "$R"
R=$(xe t1 'getent hosts deb.debian.org');   chk "crun: DNS"             "debian.org" "$R"
R=$(xe t1 'timeout 5 bash -c "echo > /dev/tcp/1.1.1.1/443" && echo EGRESS-OK')
                                            chk "crun: egress"          "EGRESS-OK" "$R"
R=$(xe t1 'timeout 3 bash -c "echo > /dev/tcp/192.168.127.254/80" && echo WB || echo WALL-OK')
                                            chk "crun: local-net wall"  "WALL-OK" "$R"
( xe t1 'sleep 5; echo CC1-ALIVE' > /tmp/cc1.log 2>&1 ) &
sleep 2
R=$(xe t1 'echo CC2-WORKS');                chk "crun: concurrent (s2)" "CC2-WORKS" "$R"
wait
chk "crun: concurrent (s1)" "CC1-ALIVE" "$(cat /tmp/cc1.log)"

echo "===== runsc (t2) ====="
$G start t2 -runtime runsc -kernel "$KERNEL" \
  -image debian-bookworm-amd64.erofs >/dev/null 2>&1
sleep 1
R=$(xe t2 'uname -r; cat /proc/1/comm');    chk "runsc: sentry boot"    "4.19.0-gvisor" "$R"
R=$(xe t2 'exit 7');                        chk "runsc: exit status"    "status 7" "$R"
R=$(xe t2 'echo SEQ2');                     chk "runsc: sequential"     "SEQ2"    "$R"
R=$(xe t2 'getent hosts deb.debian.org');   chk "runsc: DNS"            "debian.org" "$R"
R=$(xe t2 'timeout 5 bash -c "echo > /dev/tcp/1.1.1.1/443" && echo EGRESS-OK')
                                            chk "runsc: egress"         "EGRESS-OK" "$R"
R=$(xe t2 'timeout 3 bash -c "echo > /dev/tcp/192.168.127.254/80" && echo WB || echo WALL-OK')
                                            chk "runsc: local-net wall" "WALL-OK" "$R"
( xe t2 'sleep 5; echo S1-ALIVE' > /tmp/s1.log 2>&1 ) &
sleep 2
R=$(xe t2 'echo S2-WORKS');                 chk "runsc: concurrent (s2)" "S2-WORKS" "$R"
wait
chk "runsc: concurrent (s1)" "S1-ALIVE" "$(cat /tmp/s1.log)"

echo "===== shares (runsc, t3) ====="
rm -rf /tmp/sharetest && mkdir -p /tmp/sharetest && echo hostfile > /tmp/sharetest/existing.txt
$G start t3 -runtime runsc -kernel "$KERNEL" \
  -image debian-bookworm-amd64.erofs \
  -share code=/tmp/sharetest >/dev/null 2>&1
sleep 1
R=$(xe t3 'ls /host/code');                             chk "share: read"   "existing.txt" "$R"
R=$(xe t3 'mkdir /host/code/d2 && echo MK-OK');         chk "share: mkdir"  "MK-OK" "$R"
R=$(xe t3 'echo x > /host/code/f2 && echo WR-OK');      chk "share: write"  "WR-OK" "$R"
[ -f /tmp/sharetest/f2 ] && [ -d /tmp/sharetest/d2 ] && ok "share: visible on host" || bad "share: visible on host"

echo "===== OCI image (t4: alpine, offline cache hit) ====="
# the corporate network blocks registry-1.docker.io from the instance;
# the store is pre-seeded from S3 and Resolve must hit it offline
mkdir -p "$GANTRY_IMAGES"
for _ in 1 2 3; do curl -fSL --retry 3 -o /tmp/alpine-store.tar.gz "$GANTRY_STORE_URL" && break; sleep 3; done
tar xzf /tmp/alpine-store.tar.gz -C "$GANTRY_IMAGES"
$G image ls
$G start t4 -image alpine:latest 2>&1 | tail -2
sleep 1
R=$(xe t4 'head -1 /etc/os-release');             chk "image: alpine runs"     "Alpine" "$R"
R=$(xe t4 'echo PATH=$PATH');                     chk "image: config env"     "PATH=/usr/local/sbin" "$R"
R=$(xe t4 'busybox | head -1');                   chk "image: busybox links"  "BusyBox" "$R"
R=$($G image ls 2>&1);                            chk "image: ls shows pull"  "alpine" "$R"

echo "===== secrets (t5: alpine, offline) ====="
# docs/secrets.md acceptance test: a canary value must appear in the
# workload's environment inside the guest and NOWHERE in host state.
CANARY="sk-canary-$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo fixed)"
FILECANARY="sk-file-$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo fixed)"
printf '%s\n' "$FILECANARY" > /tmp/canary-file
CANARY="$CANARY" $G start t5 -secret CANARY -secret FROM_FILE=@/tmp/canary-file -image alpine:latest >/dev/null 2>&1
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
[ -n "$VPID" ] && tr '\0' '\n' < /proc/$VPID/environ 2>/dev/null | grep -qs "$CANARY" && leak="$leak environ"
[ -n "$VPID" ] && tr '\0' ' ' < /proc/$VPID/cmdline 2>/dev/null | grep -qs "$CANARY" && leak="$leak cmdline"
[ -z "$leak" ] && ok "secrets: canary absent from host state" || { bad "secrets: canary absent from host state"; echo "  leaked into:$leak"; }

R=$($G start t6 -secret TOKEN=literal-value -image alpine:latest 2>&1)
chk "secrets: literal refused" "refusing" "$R"
# Secret specs validate before any on-disk artifacts: the refused start
# must not leave a fresh per-sandbox rwlayer behind.
[ ! -e "$RWDIR/t6.ext4" ] && ok "resolver: bad spec leaves no rwlayer" || bad "resolver: bad spec leaves no rwlayer"

echo "===== bound secrets + credential helper (t7/t8: alpine, offline) ====="
# docs/credential-brokering.md workstream 1: a NAME@host secret is held
# host-side only, delivered per-use through the vsock broker behind three
# gates (binding → egress → presence), and revocable without a restart.
BOUNDCANARY="sk-bound-$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo fixed)"
BOUND_TOKEN="$BOUNDCANARY" $G start t7 -secret BOUND_TOKEN@git.test -image alpine:latest >/dev/null 2>&1
sleep 3   # guest-tools delivery races readiness; give the async push a moment

R=$(xe t7 'printenv BOUND_TOKEN || echo ABSENT'); chk "binding: bound secret NOT ambient" "ABSENT" "$R"
R=$(xe t7 'printenv GIT_CONFIG_VALUE_0');         chk "binding: git wired via env config" "/run/gantry/bin/credhelper" "$R"
R=$(xe t7 'test -x /run/gantry/bin/gantry-guest && test -L /run/gantry/bin/credhelper && echo HELPER-OK')
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
BOUND_TOKEN="$BOUNDCANARY" $G start t8 -secret BOUND_TOKEN@git.test -net-policy /tmp/netpol-t8.json -image alpine:latest >/dev/null 2>&1
sleep 3
R=$(xe t8 "$QB"); empty_cred "broker: egress policy denies out-of-allowlist host" "$R"

echo "===== secret sources with TTL (t9: file rotation, fail-closed) ====="
# docs/credential-brokering.md workstream 2: a file-backed bound secret
# resolves at REQUEST time through the daemon's TTL Store — rotating the
# file is picked up without a sandbox restart, and a broken source fails
# closed (empty answer, never a stale value).
echo "file-token-v1" > /tmp/t9-token
$G start t9 -secret 'FILE_TOKEN@git.test=@/tmp/t9-token,ttl=2s' -image alpine:latest >/dev/null 2>&1
sleep 4
QF='printf "protocol=https\nhost=git.test\n\n" | /run/gantry/bin/credhelper get'
R=$(xe t9 "$QF"); chk "source: file value delivered" "password=file-token-v1" "$R"
echo "file-token-v2" > /tmp/t9-token   # rotate on the host
sleep 3                              # past the 2s TTL
R=$(xe t9 "$QF"); chk "source: rotation picked up live" "password=file-token-v2" "$R"
rm -f /tmp/t9-token                  # source breaks after a good resolve
sleep 3
R=$(xe t9 "$QF"); empty_cred "source: fail-closed after source removal" "$R"

echo "==============================="
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
