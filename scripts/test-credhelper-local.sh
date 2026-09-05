#!/bin/bash
# test-credhelper-local.sh — local acceptance test for host-bound secrets
# and the credential helper (docs/credential-brokering.md workstream 1).
# Runs on macOS (Virtualization.framework, arm64 guests) and on Linux KVM
# hosts (x86_64 guests) — anywhere `gantry start` works. It is the local
# mirror of the t7/t8 section of scripts/aws-kvm/test-battery.sh.
#
# What it proves, offline, against a made-up host (git.test):
#   1. a -secret NAME@host value is NOT injected into the guest env
#   2. the gantry-guest helper is staged and git is wired via GIT_CONFIG_*
#   3. the broker delivers the credential for the bound host only
#   4. an unbound host gets an empty answer (git falls through)
#   5. only "NAME@host" persists in sandbox.json — never the value
#   6. secret.remove over ctl.sock revokes mid-session (no restart)
#   7. an egress policy without the host denies delivery even though the
#      value is held (a brokered token never outruns the firewall)
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

case "$(uname -m)" in
arm64|aarch64) GUESTARCH=arm64 ;;
x86_64)        GUESTARCH=x86_64 ;;
*) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

# Guest image: $IMAGE wins; then the dev-tree defaults (see
# guestasset.DefaultImage); then the image store (e.g. alpine:latest from
# `gantry image pull`).
IMAGE="${IMAGE:-}"
for c in artifacts/debian-bookworm.erofs artifacts/debian-bookworm-amd64.erofs shell-rootfs.erofs; do
	[ -z "$IMAGE" ] && [ -f "$c" ] && IMAGE="$c" && break
done
[ -z "$IMAGE" ] && IMAGE="alpine:latest"
echo "== using image: $IMAGE =="

ARTIFACTS=${GANTRY_ARTIFACTS:-$ROOT/artifacts}
mkdir -p "$ARTIFACTS"
BIN=${GANTRY_TEST_EXE:-}
OWN_BIN=0
if [ -z "$BIN" ]; then
	echo "== building gantry ($GUESTARCH) =="
	BIN=$(mktemp "${TMPDIR:-/tmp}/gantry-local.XXXXXX")
	OWN_BIN=1
	go build -o "$BIN" ./cmd/gantry || exit 1
	# macOS refuses VM creation (HV_DENIED) from a binary without the
	# hypervisor entitlement; ad-hoc sign like scripts/build.sh does.
	if [ "$(uname -s)" = Darwin ]; then
		codesign --sign - --entitlements "$ROOT/config/entitlements.plist" -f "$BIN" 2>&1 \
			| grep -v 'replacing existing signature' || true
	fi
else
	echo "== using existing gantry: $BIN =="
	[ -x "$BIN" ] || { echo "gantry binary is not executable: $BIN" >&2; exit 1; }
fi
GUEST=${GANTRY_TEST_GUEST:-$ARTIFACTS/gantry-guest-$GUESTARCH}
if [ -z "${GANTRY_TEST_GUEST:-}" ]; then
	echo "== building gantry-guest ($GUESTARCH) =="
	GOOS=linux CGO_ENABLED=0 go build -ldflags "-s -w" \
		-o "$GUEST" ./cmd/gantry-guest || exit 1
else
	echo "== using existing guest helper: $GUEST =="
	[ -s "$GUEST" ] || { echo "guest helper is missing: $GUEST" >&2; exit 1; }
fi
# Dev builds resolve guest assets via GANTRY_ARTIFACTS. Keep the host binary
# and helper in one explicit staging directory when a caller supplied it.
export GANTRY_ARTIFACTS="$ARTIFACTS"

TD=$(mktemp -d "${TMPDIR:-/tmp}/gantry-chtest.XXXXXX") || exit 1
# File-backed secret sources deliberately reject symlinked path spellings.
# Resolve aliases such as macOS /var -> /private/var before using TD/ftok.
TD=$(CDPATH= cd -- "$TD" && pwd -P) || exit 1
# GANTRY_HOME is the sandboxes root itself; nesting it keeps the rwlayer
# dir (its sibling) inside the temp tree.
export GANTRY_HOME="$TD/sandboxes"
SANDBOXES="$GANTRY_HOME"
G="$BIN"
PASS=0; FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
chk() { local n="$1" want="$2" got="$3"; if printf '%s' "$got" | grep -qa -- "$want"; then ok "$n"; else bad "$n"; printf '%s\n' "$got" | tail -4; fi; }
# empty_cred asserts the helper emitted NO credential. `gantry exec`
# prints its own client-noise lines, so the test is "no password=" (never
# "no output").
empty_cred() { local n="$1" got="$2"; if printf '%s' "$got" | grep -qa '^password='; then bad "$n"; printf '%s\n' "$got" | tail -3; else ok "$n"; fi; }
xe() { printf '%s\nexit\n' "$2" | timeout 90 "$BIN" exec "$1" 2>&1; }
# macOS has no timeout(1); run exec bare there.
if ! command -v timeout >/dev/null 2>&1; then xe() { printf '%s\nexit\n' "$2" | "$BIN" exec "$1" 2>&1; }; fi

cleanup() {
	for sandbox in ch1 ch2 ch3 chbad; do
		"$BIN" stop "$sandbox" >/dev/null 2>&1
		"$BIN" delete "$sandbox" >/dev/null 2>&1
	done
	rm -rf "$TD"
	[ "$OWN_BIN" = 0 ] || rm -f -- "$BIN"
}
trap cleanup EXIT HUP INT TERM

CANARY="sk-bound-$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid 2>/dev/null || echo fixed)"
QB='printf "protocol=https\nhost=git.test\n\n" | /run/gantry/bin/credhelper get'
QN='printf "protocol=https\nhost=evil.test\n\n" | /run/gantry/bin/credhelper get'

echo "===== bound secrets + credential helper (ch1) ====="
OUT=$(BOUND_TOKEN="$CANARY" "$BIN" start ch1 -secret BOUND_TOKEN@git.test -image "$IMAGE" 2>&1)
if [ $? -ne 0 ]; then
	echo "start ch1 FAILED — daemon output:"; printf '%s\n' "$OUT"
	DL=$(find "$GANTRY_HOME/ch1" -name daemon.log 2>/dev/null | head -1)
	[ -n "$DL" ] && { echo "---- $DL ----"; tail -20 "$DL"; }
	exit 1
fi
sleep 3   # guest-tools delivery races readiness; give the async push a moment

R=$(xe ch1 'printenv BOUND_TOKEN || echo ABSENT'); chk "binding: bound secret NOT ambient" "ABSENT" "$R"
R=$(xe ch1 'printenv GIT_CONFIG_VALUE_0');         chk "binding: git wired via env config" "/run/gantry/bin/credhelper" "$R"
R=$(xe ch1 'test -x /run/gantry/bin/gantry-guest && test -x /run/gantry/bin/credhelper && echo HELPER-OK')
if printf '%s' "$R" | grep -qa "HELPER-OK"; then ok "binding: helper staged in guest"; else
	bad "binding: helper staged in guest"; printf '%s\n' "$R" | tail -4
	DL=$(find "$GANTRY_HOME/ch1" -name daemon.log 2>/dev/null | head -1)
	[ -n "$DL" ] && { echo "---- $DL (tail) ----"; tail -8 "$DL"; }
fi

# Diagnostics: hash comparison separates delivery corruption from a
# runtime crash; `version` separates binary startup from the vsock path.
DL=$(find "$GANTRY_HOME/ch1" -name daemon.log 2>/dev/null | head -1)
[ -n "$DL" ] && { echo "---- $DL (guest-tools lines) ----"; grep -a "guest" "$DL" | tail -6; }
HOSTSUM=$(shasum -a 256 "$GUEST" 2>/dev/null | awk '{print $1}')
[ -z "$HOSTSUM" ] && HOSTSUM=$(sha256sum "$GUEST" 2>/dev/null | awk '{print $1}')
HOSTSIZE=$(wc -c < "$GUEST" | tr -d ' ')
R=$(xe ch1 'wc -c < /run/gantry/bin/gantry-guest 2>/dev/null; sha256sum /run/gantry/bin/gantry-guest 2>/dev/null || shasum -a 256 /run/gantry/bin/gantry-guest 2>/dev/null')
GUESTSUM=$(printf '%s' "$R" | grep -o '[0-9a-f]\{64\}' | head -1)
GUESTSIZE=$(printf '%s' "$R" | grep -o '^[0-9]\+' | head -1)
echo "diag: host=$HOSTSUM ($HOSTSIZE bytes) guest=$GUESTSUM ($GUESTSIZE bytes)"
[ -n "$HOSTSUM" ] && [ "$HOSTSUM" = "$GUESTSUM" ] && ok "diag: delivered binary intact" || bad "diag: delivered binary intact"
R=$(xe ch1 '/run/gantry/bin/gantry-guest version 2>&1'); chk "diag: gantry-guest version runs" "gantry-guest" "$R"
R=$(xe ch1 "GANTRY_GUEST_DEBUG=1 $QB" 2>&1); echo "diag: debug query output:"; printf '%s\n' "$R" | tail -6

R=$(xe ch1 "$QB"); chk "broker: delivers bound credential" "password=$CANARY" "$R"
                   chk "broker: git username convention" "username=x-access-token" "$R"
R=$(xe ch1 "$QN"); empty_cred "broker: unbound host answers empty" "$R"

grep -q "BOUND_TOKEN@git.test" "$SANDBOXES/ch1/sandbox.json" 2>/dev/null \
	&& ok "binding: name+binding persisted" || bad "binding: name+binding persisted"
grep -q "$CANARY" "$SANDBOXES/ch1/sandbox.json" 2>/dev/null \
	&& bad "binding: value NOT in sandbox.json" || ok "binding: value NOT in sandbox.json"

echo "===== mid-session revocation (ch1) ====="
if command -v python3 >/dev/null 2>&1; then
	R=$(python3 - <<'PYEOF'
import json, os, socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(os.path.join(os.environ["GANTRY_HOME"], "ch1", "ctl.sock"))
s.sendall(b'{"op":"secret.remove","id":"rvk","secret":{"name":"BOUND_TOKEN"}}\n')
sys.stdout.write(s.makefile().readline())
PYEOF
	)
	chk "revocation: control op accepted" '"ok":true' "$R"
	R=$(xe ch1 "$QB"); empty_cred "revocation: broker answers empty after remove" "$R"
	grep -q "BOUND_TOKEN" "$SANDBOXES/ch1/sandbox.json" 2>/dev/null \
		&& bad "revocation: name dropped from sandbox.json" || ok "revocation: name dropped from sandbox.json"
else
	bad "revocation: python3 unavailable for the ctl.sock frame"
fi

echo "===== egress gate (ch2) ====="
NP="$GANTRY_HOME/netpol.json"
cat > "$NP" <<'EOF'
{"default":"deny","allowLocal":true,"allowDomains":["example.com"]}
EOF
BOUND_TOKEN="$CANARY" "$BIN" start ch2 -secret BOUND_TOKEN@git.test -net-policy "$NP" -image "$IMAGE" >/dev/null 2>&1
if [ $? -ne 0 ]; then echo "start ch2 FAILED"; bad "egress: ch2 starts"; else
sleep 3
R=$(xe ch2 "$QB"); empty_cred "broker: egress policy denies out-of-allowlist host" "$R"
fi

echo "===== secret sources with TTL (ch3) ====="
# Workstream 2: file-backed bound secret resolves at request time; host
# rotation is picked up without a restart; a broken source fails closed.
echo "file-canary-v1" > "$TD/ftok"
"$BIN" start ch3 -secret "FILE_TOK@git.test=@$TD/ftok,ttl=2s" -image "$IMAGE" >/dev/null 2>&1
if [ $? -ne 0 ]; then echo "start ch3 FAILED"; bad "source: ch3 starts"; else
sleep 3
QF='printf "protocol=https\nhost=git.test\n\n" | /run/gantry/bin/credhelper get'
R=$(xe ch3 "$QF"); chk "source: file value delivered" "password=file-canary-v1" "$R"
echo "file-canary-v2" > "$TD/ftok"
sleep 3
R=$(xe ch3 "$QF"); chk "source: rotation picked up live" "password=file-canary-v2" "$R"
rm -f "$TD/ftok"
sleep 3
R=$(xe ch3 "$QF"); empty_cred "source: fail-closed after source removal" "$R"
fi

echo "===== resolver ordering ====="
# A refused -secret spec must fail BEFORE any on-disk artifacts exist:
# no fresh 512 MiB rwlayer left behind.
R=$("$BIN" start chbad -secret TOKEN=literal-value -image "$IMAGE" 2>&1)
chk "resolver: literal secret refused" "refusing" "$R"
[ ! -e "$TD/rwlayers/chbad.ext4" ] && ok "resolver: bad spec leaves no rwlayer" || bad "resolver: bad spec leaves no rwlayer"

echo "==============================="
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
