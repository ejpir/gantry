#!/usr/bin/env bash
# pi-container.sh — build, run, and attach to a pi agent in a container.
#
# The agent (LLM calls, tools, extensions, sessions) lives inside the
# container; your host runs only the thin TUI via `pi attach`.
# Works on the dev sandbox (linux) and on macOS (Docker Desktop or podman).
#
# Usage:
#   ./pi-container.sh build                build the pi-agent image
#   ./pi-container.sh run [project-dir]    start the agent container (default project: cwd)
#   ./pi-container.sh attach               attach the stock pi TUI (auto transport)
#   ./pi-container.sh attach --sock        attach via bind-mounted unix socket
#   ./pi-container.sh attach --exec        attach via container-exec stdio
#   ./pi-container.sh stop                 stop and remove the container
#   ./pi-container.sh logs                 follow agent container logs
set -euo pipefail

IMAGE=pi-attach-agent
NAME=pi-agent
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PI_REPO=$(cd "$SCRIPT_DIR/../../../pi" && pwd)
SOCK_DIR=${PI_SOCK_DIR:-/tmp/pi-attach}
AUTH_FILE=${PI_AUTH_FILE:-$HOME/.pi/agent/auth.json}

# --- container CLI + build strategy per platform ---------------------------
if [[ $(uname) == Darwin ]]; then
	# Docker Desktop / podman on macOS: plain build (BuildKit ships with the
	# app; bind-mounted unix sockets through the VM layer are unreliable,
	# so exec is the default attach transport). Direct egress: no proxy.
	if command -v docker >/dev/null 2>&1; then CLI=docker; else CLI=podman; fi
	BUILD=(build)
	BUILD_ARGS=()
	RUN_PROXY_ENV=()
	DEFAULT_TRANSPORT=sock
else
	# Dev sandbox: the docker-container buildx builder boot image is
	# Docker-Hub-blocked; use the daemon's built-in builder explicitly.
	# Egress goes through the sandbox proxy, reachable from containers as
	# gateway.docker.internal:3128 (verified; 192.168.1.1 is NOT reachable).
	CLI="docker --context default"
	BUILD=(buildx build --builder default --load)
	BUILD_ARGS=(--build-arg PROXY=http://gateway.docker.internal:3128)
	RUN_PROXY_ENV=(-e HTTPS_PROXY=http://gateway.docker.internal:3128
		-e HTTP_PROXY=http://gateway.docker.internal:3128)
	DEFAULT_TRANSPORT=sock
fi

stage_inputs() {
	mkdir -p "$PI_REPO/.pi-container/certs"
	if ! ls "$PI_REPO/.pi-container/certs"/*.crt >/dev/null 2>&1; then
		if [[ -d /usr/local/share/ca-certificates ]]; then
			cp /usr/local/share/ca-certificates/*.crt "$PI_REPO/.pi-container/certs/" 2>/dev/null || true
		elif [[ $(uname) == Darwin ]]; then
			# macOS: export the system keychain roots (includes corp CAs).
			security find-certificate -a -p /Library/Keychains/System.keychain > "$PI_REPO/.pi-container/certs/keychain-roots.crt" || true
		fi
	fi
	if ! ls "$PI_REPO/.pi-container/certs"/*.crt >/dev/null 2>&1; then
		echo "no corporate CA certs staged (needed for proxy MITM)" >&2
		exit 1
	fi
	cp "$SCRIPT_DIR/settings.json" "$PI_REPO/.pi-container/settings.json"

	# Context hygiene (generated, not committed): source only — the image
	# runs npm ci + build itself, so node_modules/dist are excluded.
	cat > "$PI_REPO/.dockerignore" <<'EOF'
.git
node_modules
**/node_modules
**/dist
**/*.test.ts
**/test/
**/.pi-test-*
EOF
}

cmd_build() {
	stage_inputs
	# shellcheck disable=SC2068
	$CLI ${BUILD[@]} ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"} -f "$SCRIPT_DIR/Dockerfile" -t "$IMAGE" "$PI_REPO"
	rm -f "$PI_REPO/.dockerignore"
	echo "built $IMAGE"
}

RELAY_PORT=7680

cmd_run() {
	local project
	project=$(cd "${1:-.}" && pwd)
	mkdir -p "$SOCK_DIR"
	$CLI rm -f "$NAME" >/dev/null 2>&1 || true
	if [[ $(uname) == Darwin ]]; then
		# No bind-mounted socket: pi listens container-local, a relay carries
		# it to 127.0.0.1:$RELAY_PORT, a host relay serves a real unix socket.
		$CLI run -d --name "$NAME" \
			-p 127.0.0.1:$RELAY_PORT:$RELAY_PORT \
			-v "$AUTH_FILE:/home/node/.pi/agent/auth.json" \
			-v "$project:/work" \
			-w /work \
			"$IMAGE" --mode rpc --sock /tmp/agent.sock
		$CLI cp "$SCRIPT_DIR/relay.js" "$NAME:/tmp/relay.js"
		$CLI exec -d "$NAME" node /tmp/relay.js 0.0.0.0:$RELAY_PORT /tmp/agent.sock
	else
		$CLI run -d --name "$NAME" \
			${RUN_PROXY_ENV[@]+"${RUN_PROXY_ENV[@]}"} \
			-v "$SOCK_DIR:/sock" \
			-v "$AUTH_FILE:/home/node/.pi/agent/auth.json" \
			-v "$project:/work" \
			-w /work \
			"$IMAGE" --mode rpc --sock /sock/agent.sock
	fi
	echo "agent container '$NAME' running; project at /work: $project"
}

# mac: ensure the host-side unix->TCP relay is up, print the socket path.
host_relay() {
	if ! $CLI exec "$NAME" test -S /tmp/agent.sock 2>/dev/null; then
		sleep 2 # agent still booting
	fi
	if ! nc -z 127.0.0.1 $RELAY_PORT 2>/dev/null; then
		echo "container relay not reachable on 127.0.0.1:$RELAY_PORT" >&2
		exit 1
	fi
	pkill -f "relay.js $SOCK_DIR/agent.sock" 2>/dev/null || true
	nohup node "$SCRIPT_DIR/relay.js" "$SOCK_DIR/agent.sock" 127.0.0.1:$RELAY_PORT \
		> "$SOCK_DIR/relay.log" 2>&1 &
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		[[ -S $SOCK_DIR/agent.sock ]] && break
		sleep 0.3
	done
}

pi_attach() {
	node "$PI_REPO/packages/coding-agent/dist/cli.js" attach "$@"
}

cmd_attach() {
	local transport=${1:-$DEFAULT_TRANSPORT}
	transport=${transport#--}
	if [[ $transport == sock ]]; then
		if [[ $(uname) == Darwin ]]; then host_relay; fi
		pi_attach --sock "$SOCK_DIR/agent.sock"
	else
		pi_attach --cmd "$CLI exec -i $NAME node /opt/pi/packages/coding-agent/dist/cli.js --mode rpc"
	fi
}

cmd_stop() { $CLI rm -f "$NAME"; }
cmd_logs() { $CLI logs -f "$NAME"; }

case "${1:-}" in
	build) cmd_build ;;
	run) shift; cmd_run "$@" ;;
	attach) shift; cmd_attach "$@" ;;
	stop) cmd_stop ;;
	logs) cmd_logs ;;
	*) grep '^#' "$0" | head -24; exit 1 ;;
esac
