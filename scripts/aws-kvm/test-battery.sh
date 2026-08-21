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

for s in t1 t2 t3 t4 t10 t11; do $G stop "$s" >/dev/null 2>&1; done
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

echo "===== OAuth custody (t10: mock provider, refresh token held on host) ====="
# docs/credential-brokering.md workstream 3: with -oauth-custody the guest
# helper runs the PKCE flow but the DAEMON exchanges the code and holds
# the refresh token host-side; the guest auth file carries a short-lived
# access token plus a sentinel. A mock authorization server on the
# instance loopback stands in for the real provider.
cat > /tmp/mock-as.py <<'PYEOF'
import json
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
HTTPServer(("127.0.0.1", 18999), H).serve_forever()
PYEOF
pkill -f mock-as.py 2>/dev/null; sleep 1  # a crashed prior run may still hold the port
rm -f /tmp/mock-as-grants.log
python3 /tmp/mock-as.py &
MOCKPID=$!
sleep 1
export GANTRY_OAUTH_TOKEN_URL_CLAUDE=http://127.0.0.1:18999/token
$G start t10 -oauth-custody -image alpine:latest >/dev/null 2>&1
sleep 4
# The login blocks until the callback lands: run it in the background,
# scrape the authorize URL for its dynamic port + state, and play the
# browser redirect with curl.
( printf '/run/gantry/bin/gantry-guest oauth login claude\nexit\n' | timeout 60 $G exec t10 > /tmp/t10-login.log 2>&1 ) &
sleep 4
URL=$(grep -oa 'https://claude.ai/oauth/authorize[^ ]*' /tmp/t10-login.log | head -1)
CPORT=$(printf '%s' "$URL" | sed -n 's/.*127\.0\.0\.1%3A\([0-9]*\)%2Fcallback.*/\1/p')
CSTATE=$(printf '%s' "$URL" | sed -n 's/.*[?&]state=\([A-Za-z0-9_-]*\).*/\1/p')
curl -s "http://127.0.0.1:$CPORT/callback?code=mock-code&state=$CSTATE" > /tmp/t10-callback.html
# The guest helper polls oauth.status on a ~1s cadence; give the
# completion line time to land in the session log instead of racing it.
for _ in $(seq 1 15); do grep -qa "tokens held on host" /tmp/t10-login.log && break; sleep 1; done
R=$(cat /tmp/t10-callback.html);            chk "custody: callback consumed host-side"        "Login complete" "$R"
R=$(cat /tmp/t10-login.log);                chk "custody: login completed in guest"            "tokens held on host" "$R"
R=$(xe t10 'cat /root/.claude/.credentials.json')
                                            chk "custody: guest holds an access token"        "at-mock-" "$R"
                                            chk "custody: guest refresh token is a sentinel"  "gantry-custody-refresh-held-on-host" "$R"
R=$(cat "$GANTRY_HOME/t10/oauth-tokens.json")
                                            chk "custody: refresh token held host-side"       "rt-mock-1" "$R"
M=$(stat -c %a "$GANTRY_HOME/t10/oauth-tokens.json")
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
                                            chk "custody: session restored after restart"     "session restored from disk" "$R"
R=$(xe t10 '/run/gantry/bin/gantry-guest oauth login github 2>&1')
                                            chk "custody: unknown provider refused"           "no custody login" "$R"
kill $MOCKPID 2>/dev/null

echo "===== MCP gateway (t11: fs server via mcp-proxy, containment) ====="
# docs/mcp-gateway.md milestone 1: the agent speaks MCP (NDJSON stdio) to
# gantry-guest mcp-proxy, the host gateway muxes to a contained fs server
# spawned guest-side as an unprivileged user (never root).
$G start t11 -mcp -mcp-fs-root /work -mcp-fs-user nobody -image alpine:latest >/dev/null 2>&1
sleep 4
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
{ echo 'cat > /tmp/reqs <<MEOF'; cat /tmp/t11-reqs.ndjson; echo 'MEOF'; echo 'exit'; } | timeout 90 $G exec t11 >/dev/null 2>&1
R=$(printf '{ cat /tmp/reqs; sleep 4; } | /run/gantry/bin/gantry-guest mcp-proxy\nexit\n' | timeout 60 $G exec t11 2>&1)
L2=$(printf '%s' "$R" | grep -a '"id":2');  chk "mcp: tools/list exposes fs__read_file"      "fs__read_file" "$L2"
if printf '%s' "$L2" | grep -qa 'github-authorize'; then bad "mcp: auth tool hidden from listing"; else ok "mcp: auth tool hidden from listing"; fi
L3=$(printf '%s' "$R" | grep -a '"id":3');  chk "mcp: read_file round trip"                 "hello-mcp" "$L3"
L4=$(printf '%s' "$R" | grep -a '"id":4');  chk "mcp: symlink escape is an error"           '"isError":true' "$L4"
if printf '%s' "$L4" | grep -qa 'root:'; then bad "mcp: symlink escape leaked /etc/passwd"; else ok "mcp: symlink escape leaked nothing"; fi
L5=$(printf '%s' "$R" | grep -a '"id":5');  chk "mcp: unlisted tool denied"                 "unknown or disallowed" "$L5"
L6=$(printf '%s' "$R" | grep -a '"id":6');  chk "mcp: authorize tool denied"                "unknown or disallowed" "$L6"
R=$($G audit t11);                          chk "mcp: calls audited host-side"              "mcp: call fs__read_file" "$R"
                                            chk "mcp: denies audited"                      "mcp: denied call fs__write_file" "$R"

echo "==============================="
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
