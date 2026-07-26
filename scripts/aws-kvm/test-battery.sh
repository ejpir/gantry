#!/bin/bash
# test-battery.sh — the gantry x86_64 test suite. Runs ON the test
# instance (via ssm.py / run-tests.sh). Expects /opt/gantry populated;
# if GANTRY_ASSET_URL is set, (re)downloads the gantry binary first —
# NOTE: the sandbox daemons hold the ttrpc client, so sandboxes are
# always restarted after a binary swap (this script stops them).
set +e
cd /opt/gantry || exit 1

G=./gantry-linux-amd64
PASS=0; FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
chk() { local n="$1" want="$2" got="$3"; if printf '%s' "$got" | grep -qa -- "$want"; then ok "$n"; else bad "$n"; printf '%s\n' "$got" | tail -4; fi; }
xe() { printf '%s\nexit\n' "$2" | timeout 90 $G exec "$1" 2>&1; }

echo "== environment =="
uname -m; ls -la /dev/kvm || echo "NO /dev/kvm!"

for s in t1 t2 t3 t4; do $G stop "$s" >/dev/null 2>&1; done
rm -rf /tmp/.gantry/sandboxes/t* /root/.gantry/sandboxes/t* /tmp/.gantry/images /tmp/.gantry/rwlayers
# rwlayers are per-sandbox defaults now (auto-created, flock'd, image-paired)

echo "===== crun (t1) ====="
$G start t1 -kernel nerdbox-kernel-x86_64 -rootfs nerdbox-rootfs-x86_64.erofs \
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
$G start t2 -runtime runsc -kernel nerdbox-kernel-x86_64 \
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
$G start t3 -runtime runsc -kernel nerdbox-kernel-x86_64 \
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
mkdir -p /tmp/.gantry/images
for _ in 1 2 3; do curl -fSL --retry 3 -o /tmp/alpine-store.tar.gz "$GANTRY_STORE_URL" && break; sleep 3; done
tar xzf /tmp/alpine-store.tar.gz -C /tmp/.gantry/images
$G image ls
$G start t4 -image alpine:latest 2>&1 | tail -2
sleep 1
R=$(xe t4 'head -1 /etc/os-release');             chk "image: alpine runs"     "Alpine" "$R"
R=$(xe t4 'echo PATH=$PATH');                     chk "image: config env"     "PATH=/usr/local/sbin" "$R"
R=$(xe t4 'busybox | head -1');                   chk "image: busybox links"  "BusyBox" "$R"
R=$($G image ls 2>&1);                            chk "image: ls shows pull"  "alpine" "$R"

echo "==============================="
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
