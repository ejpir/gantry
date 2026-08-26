#!/bin/bash
# Validate the SSH gateway and nested Dev Containers profile on a real KVM host.
# The runner stages fresh host/guest binaries and the current curated IDE image
# under /opt/gantry before invoking this script through SSM.
set -euo pipefail

ROOT=${GANTRY_TEST_ROOT:-/opt/gantry}
G=${GANTRY_TEST_EXE:-$ROOT/gantry-linux-amd64}
KERNEL=${GANTRY_TEST_KERNEL:-$ROOT/nerdbox-kernel-x86_64}
ROOTFS=${GANTRY_TEST_ROOTFS:-$ROOT/nerdbox-rootfs-x86_64.erofs}
IMAGE=${GANTRY_TEST_IDE_IMAGE:-$ROOT/gantry-ide-image-x86_64.erofs}
GUEST=${GANTRY_TEST_GUEST:-$ROOT/gantry-guest-x86_64}
SANDBOX=${GANTRY_TEST_SANDBOX:-ssh-devcontainers-kvm}
STATE_ROOT=${GANTRY_HOME:-$ROOT/state-ssh-devcontainers}
CONFIG=$STATE_ROOT/$SANDBOX/sandbox.json
LOG=$STATE_ROOT/$SANDBOX/daemon.log
PADDED_GUEST=$ROOT/gantry-guest-x86_64-padded
SFTP_OUT=$(mktemp /tmp/gantry-sftp.XXXXXX)

export HOME=${HOME:-/root}
export GANTRY_HOME=$STATE_ROOT
export GANTRY_ARTIFACTS=$ROOT
export GANTRY_BOOT_TIMING=1

pass() { echo "PASS ssh/devcontainers: $*"; }
fail() { echo "FAIL ssh/devcontainers: $*" >&2; exit 1; }
run() { echo "+ $*"; "$@"; }
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  "$G" ssh setup --remove >/dev/null 2>&1 || true
  "$G" stop "$SANDBOX" >/dev/null 2>&1 || true
  "$G" delete "$SANDBOX" >/dev/null 2>&1 || true
  rm -f -- "$PADDED_GUEST" "$SFTP_OUT"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

for path in "$G" "$KERNEL" "$ROOTFS" "$IMAGE" "$GUEST"; do
  [ -s "$path" ] || fail "required asset missing: $path"
done
command -v ssh >/dev/null || fail "OpenSSH client is not installed on the field host"
command -v sftp >/dev/null || fail "SFTP client is not installed on the field host"

"$G" stop "$SANDBOX" >/dev/null 2>&1 || true
"$G" delete "$SANDBOX" >/dev/null 2>&1 || true

run "$G" start "$SANDBOX" \
  -kernel "$KERNEL" -rootfs "$ROOTFS" \
  -ssh -devcontainers -mem 4096 -cpus 2 -disk-size 2048

doctor=$("$G" ssh doctor "$SANDBOX" 2>&1)
printf '%s\n' "$doctor"
grep -q 'SSH enabled[[:space:]]*yes' <<<"$doctor" || fail "SSH doctor did not report SSH enabled"
grep -q 'Dev Containers[[:space:]]*yes' <<<"$doctor" || fail "SSH doctor did not report Dev Containers enabled"
grep -q 'Podman[[:space:]]*yes' <<<"$doctor" || fail "SSH doctor did not find Podman"
pass "doctor verifies the curated image and nested-runtime devices"

direct=$("$G" ssh "$SANDBOX" -- /bin/echo GANTRY-DIRECT-SSH 2>&1)
printf '%s\n' "$direct"
grep -q GANTRY-DIRECT-SSH <<<"$direct" || fail "direct gantry ssh command failed"
pass "direct gantry ssh command"

run "$G" ssh setup
managed=$(ssh -o BatchMode=yes "$SANDBOX.gantry" /bin/echo GANTRY-MANAGED-SSH 2>&1)
printf '%s\n' "$managed"
grep -q GANTRY-MANAGED-SSH <<<"$managed" || fail "managed *.gantry SSH command failed"
pass "managed *.gantry OpenSSH connection"

run ssh -o BatchMode=yes "$SANDBOX.gantry" 'printf GANTRY-SFTP > "$HOME/gantry-sftp-field.txt"'
printf 'get /home/gantry/gantry-sftp-field.txt %s\n' "$SFTP_OUT" | sftp -q -b - "$SANDBOX.gantry"
grep -qx GANTRY-SFTP "$SFTP_OUT" || fail "SFTP round trip returned the wrong content"
pass "SFTP subsystem round trip"

build_script=$(cat <<'EOF'
set -eux
exec 2>&1
context=$HOME/gantry-inner-image
rm -rf "$context"
mkdir -p "$context/rootfs"
for binary in /bin/sh /bin/echo /bin/cat; do
  target=$context/rootfs$binary
  mkdir -p "$(dirname "$target")"
  cp -L "$binary" "$target"
  ldd "$binary" | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^\//) { print $i; break } }'
done | sort -u | while IFS= read -r library; do
  target=$context/rootfs$library
  mkdir -p "$(dirname "$target")"
  cp -L "$library" "$target"
done
cat >"$context/Dockerfile" <<'DOCKERFILE'
FROM scratch
COPY rootfs /
CMD ["/bin/sh"]
DOCKERFILE
docker build -t localhost/gantry-field-inner:latest "$context"
docker volume rm -f gantry-field-volume >/dev/null 2>&1 || true
docker volume create gantry-field-volume >/dev/null
docker run --rm localhost/gantry-field-inner:latest /bin/echo GANTRY-NESTED-PODMAN
docker run --rm -v gantry-field-volume:/data localhost/gantry-field-inner:latest /bin/sh -c 'printf GANTRY-VOLUME-PERSISTED > /data/marker'
sudo mkdir -p /run/libpod/gantry-field-stale
sudo touch /run/libpod/gantry-field-stale/marker
sudo touch /var/lib/containers/gantry-field-persistent-marker
EOF
)
nested=$("$G" exec "$SANDBOX" -- sh -c "$build_script" 2>&1)
printf '%s\n' "$nested"
grep -q GANTRY-NESTED-PODMAN <<<"$nested" || fail "offline nested Podman image did not run"
pass "offline nested Podman build, run, and volume write"

boot_before=$("$G" exec "$SANDBOX" -- cat /proc/sys/kernel/random/boot_id | grep -Eo '[0-9a-f]{8}-[0-9a-f-]{27}' | tail -1)
[ -n "$boot_before" ] || fail "could not read the initial VM boot ID"
run "$G" stop "$SANDBOX"
cp "$GUEST" "$PADDED_GUEST"
truncate -s $((60 * 1024 * 1024)) "$PADDED_GUEST"
chmod 0755 "$PADDED_GUEST"
python3 - "$CONFIG" "$PADDED_GUEST" <<'PY'
import json, os, sys
path, helper = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    config = json.load(stream)
config["guest_tools"] = os.path.abspath(helper)
temporary = path + ".field.tmp"
with open(temporary, "w", encoding="utf-8") as stream:
    json.dump(config, stream, indent=2)
    stream.write("\n")
os.replace(temporary, path)
PY
: >"$LOG"
start_ms=$(date +%s%3N)
run "$G" resume "$SANDBOX"
ready_ms=$(date +%s%3N)
early=$("$G" ssh "$SANDBOX" -- /bin/echo GANTRY-EARLY-SSH 2>&1)
printf '%s\n' "$early"
grep -q GANTRY-EARLY-SSH <<<"$early" || fail "early SSH request did not wait for helper delivery"
ready_line=$(grep -n 'guest RPC connected (READY)' "$LOG" | tail -1 | cut -d: -f1)
delivered_line=$(grep -n 'guest tools delivered' "$LOG" | tail -1 | cut -d: -f1)
[ -n "$ready_line" ] && [ -n "$delivered_line" ] || fail "missing readiness or guest-helper delivery evidence"
[ "$ready_line" -lt "$delivered_line" ] || fail "guest helper completed before readiness was published"
pass "readiness returned in $((ready_ms - start_ms)) ms before padded helper delivery; early SSH waited"

boot_after=$("$G" exec "$SANDBOX" -- cat /proc/sys/kernel/random/boot_id | grep -Eo '[0-9a-f]{8}-[0-9a-f-]{27}' | tail -1)
[ -n "$boot_after" ] || fail "could not read the resumed VM boot ID"
[ "$boot_before" != "$boot_after" ] || fail "VM boot ID did not change across stop/resume"
restart_check=$("$G" exec "$SANDBOX" -- env "GANTRY_OLD_BOOT_ID=$boot_before" sh -c '
set -eux
exec 2>&1
sudo mkdir -p /run/libpod/gantry-field-stale /run/gantry/podman
sudo touch /run/libpod/gantry-field-stale/marker
printf "%s\n" "$GANTRY_OLD_BOOT_ID" | sudo tee /run/gantry/podman/boot-id >/dev/null
sudo test -e /run/libpod/gantry-field-stale/marker
env DOCKER_HOST=tcp://127.0.0.1:1 DOCKER_CONTEXT=bogus CONTAINER_HOST=tcp://127.0.0.1:2 XDG_RUNTIME_DIR=/missing \
  docker run --rm -v gantry-field-volume:/data localhost/gantry-field-inner:latest /bin/cat /data/marker
sudo test ! -e /run/libpod/gantry-field-stale
sudo test -e /var/lib/containers/gantry-field-persistent-marker
test "$(cat /proc/sys/kernel/random/boot_id)" = "$(sudo cat /run/gantry/podman/boot-id)"
' 2>&1)
printf '%s\n' "$restart_check"
grep -q GANTRY-VOLUME-PERSISTED <<<"$restart_check" || fail "nested image or volume did not persist across resume"
pass "boot transition clears only stale Podman run state and ignores inherited engine endpoints"

run "$G" stop "$SANDBOX"
python3 - "$CONFIG" <<'PY'
import json, os, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as stream:
    config = json.load(stream)
config.pop("guest_tools", None)
config.pop("runtime", None)
temporary = path + ".field.tmp"
with open(temporary, "w", encoding="utf-8") as stream:
    json.dump(config, stream, indent=2)
    stream.write("\n")
os.replace(temporary, path)
PY
run "$G" resume "$SANDBOX"
legacy=$("$G" ssh "$SANDBOX" -- /bin/echo GANTRY-LEGACY-FALLBACK 2>&1)
printf '%s\n' "$legacy"
grep -q GANTRY-LEGACY-FALLBACK <<<"$legacy" || fail "daemon did not resolve omitted guest_tools beside its executable"
run "$G" configure "$SANDBOX" -ssh -devcontainers
python3 - "$CONFIG" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    config = json.load(stream)
if config.get("runtime") != "crun":
    raise SystemExit("configure did not normalize omitted runtime to crun")
PY
final_nested=$("$G" exec "$SANDBOX" -- env DOCKER_HOST=tcp://127.0.0.1:1 docker run --rm localhost/gantry-field-inner:latest /bin/echo GANTRY-FINAL-NESTED 2>&1)
printf '%s\n' "$final_nested"
grep -q GANTRY-FINAL-NESTED <<<"$final_nested" || fail "nested runtime failed after legacy-profile resume"
pass "legacy runtime normalization and cwd-independent guest-helper fallback"

pass "Linux KVM SSH and Dev Containers field validation complete"
