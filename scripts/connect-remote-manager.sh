#!/usr/bin/env bash
# Register a Gantry manager that is reachable only through an SSH jump host.
# Run this script on the client host. It copies the manager's public CA and
# bearer token over SSH, opens a persistent local tunnel, and adds the Gantry
# remote profile.
#
# Example:
#   JUMP=root@gateway.example \
#   MANAGER=gantry@192.168.1.160 \
#   GANTRY_BIN=./gantry \
#   ./scripts/connect-remote-manager.sh
#
# Optional variables:
#   REMOTE_NAME=home-lab       local Gantry profile name
#   MANAGER_HOST=192.168.1.160 tunnel destination as resolved by the jump host
#   MANAGER_PORT=8443          manager TLS port
#   MANAGER_STATE=.gantry      state path relative to the manager SSH home
#   LOCAL_PORT=18443           client-side tunnel port
#   FINGERPRINT=sha256:...     expected leaf pin; otherwise copied server.crt
#   GANTRY_TUNNEL_DIR=...      SSH control-socket directory
#
# Stop the background tunnel with the same JUMP and REMOTE_NAME:
#   JUMP=root@gateway.example ./scripts/connect-remote-manager.sh --stop

set -Eeuo pipefail

REMOTE_NAME="${REMOTE_NAME:-home-lab}"
JUMP="${JUMP:-}"
MANAGER="${MANAGER:-}"
MANAGER_HOST="${MANAGER_HOST:-${MANAGER##*@}}"
MANAGER_PORT="${MANAGER_PORT:-8443}"
MANAGER_STATE="${MANAGER_STATE:-.gantry}"
LOCAL_PORT="${LOCAL_PORT:-18443}"
GANTRY_BIN="${GANTRY_BIN:-gantry}"
FINGERPRINT="${FINGERPRINT:-}"

state_dir="${GANTRY_TUNNEL_DIR:-$HOME/.gantry/tunnels}"
control_socket="$state_dir/$REMOTE_NAME.sock"

usage() {
  cat >&2 <<EOF
usage:
  JUMP=user@jump-host MANAGER=user@manager-host [GANTRY_BIN=gantry] $0
  JUMP=user@jump-host $0 --stop
EOF
}

if [[ -z "$JUMP" ]]; then
  echo "JUMP is required (for example: JUMP=root@gateway.example)." >&2
  usage
  exit 2
fi

mkdir -p "$state_dir"
chmod 700 "$state_dir"

stop_tunnel() {
  if ssh -S "$control_socket" -O check "$JUMP" >/dev/null 2>&1; then
    ssh -S "$control_socket" -O exit "$JUMP" >/dev/null
    echo "Stopped Gantry tunnel '$REMOTE_NAME'."
  else
    rm -f "$control_socket"
    echo "Gantry tunnel '$REMOTE_NAME' is not running."
  fi
}

if [[ "${1:-}" == "--stop" ]]; then
  stop_tunnel
  exit 0
elif (( $# != 0 )); then
  usage
  exit 2
fi

if [[ -z "$MANAGER" || -z "$MANAGER_HOST" ]]; then
  echo "MANAGER is required (for example: MANAGER=gantry@192.168.1.160)." >&2
  usage
  exit 2
fi

for command in ssh scp openssl "$GANTRY_BIN"; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Missing required command: $command" >&2
    exit 1
  fi
done

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/gantry-connect.XXXXXX")"
tunnel_started=0
cleanup() {
  status=$?
  rm -rf "$tmp_dir"
  if (( status != 0 && tunnel_started == 1 )); then
    ssh -S "$control_socket" -O exit "$JUMP" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
umask 077

ca_file="$tmp_dir/ca.crt"
server_cert="$tmp_dir/server.crt"
token_file="$tmp_dir/manager.token"

echo "Copying manager credentials through $JUMP ..."
scp -q -o "ProxyJump=$JUMP" \
  "$MANAGER:$MANAGER_STATE/serve/ca.crt" \
  "$MANAGER:$MANAGER_STATE/serve/server.crt" \
  "$MANAGER:$MANAGER_STATE/manager.token" \
  "$tmp_dir/"
chmod 600 "$token_file"

if [[ -z "$FINGERPRINT" ]]; then
  fingerprint_hex="$(openssl x509 -in "$server_cert" -outform DER | openssl dgst -sha256 -hex | awk '{print $NF}' | tr '[:upper:]' '[:lower:]')"
  if [[ ! "$fingerprint_hex" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "Could not calculate the manager certificate fingerprint." >&2
    exit 1
  fi
  FINGERPRINT="sha256:$fingerprint_hex"
fi

if ssh -S "$control_socket" -O check "$JUMP" >/dev/null 2>&1; then
  echo "Reusing the existing tunnel on localhost:$LOCAL_PORT."
else
  rm -f "$control_socket"
  echo "Opening localhost:$LOCAL_PORT -> $MANAGER_HOST:$MANAGER_PORT through $JUMP ..."
  ssh -M -S "$control_socket" -fNT \
    -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 \
    -L "127.0.0.1:$LOCAL_PORT:$MANAGER_HOST:$MANAGER_PORT" \
    "$JUMP"
  tunnel_started=1
fi

# Re-running this script refreshes the local profile and stored token.
"$GANTRY_BIN" remote rm "$REMOTE_NAME" >/dev/null 2>&1 || true
"$GANTRY_BIN" remote add "$REMOTE_NAME" "https://localhost:$LOCAL_PORT" \
  --ca "$ca_file" \
  --token-file "$token_file" \
  --fingerprint "$FINGERPRINT"
"$GANTRY_BIN" remote test "$REMOTE_NAME"

echo
echo "Connected. Example:"
echo "  $GANTRY_BIN ls -remote $REMOTE_NAME"
echo "Stop the tunnel with:"
echo "  JUMP=$JUMP REMOTE_NAME=$REMOTE_NAME $0 --stop"
