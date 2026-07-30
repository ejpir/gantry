#!/usr/bin/env bash
# pi-container.sh — build, run, and attach to a pi agent in a container.
#
# The agent (LLM calls, tools, extensions, sessions) lives inside the
# container; your host runs only the thin TUI via `pi attach --sock`.
#
# Usage:
#   ./pi-container.sh build                build the pi-agent image
#   ./pi-container.sh run [project-dir]    start the agent container (default project: cwd)
#   ./pi-container.sh attach               attach the stock pi TUI from the host
#   ./pi-container.sh exec                 attach via docker-exec stdio transport instead
#   ./pi-container.sh stop                 stop and remove the container
#   ./pi-container.sh logs                 follow agent container logs
set -euo pipefail

IMAGE=pi-attach-agent
NAME=pi-agent
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PI_REPO=$(cd "$SCRIPT_DIR/../../../pi" && pwd)
SOCK_DIR=${PI_SOCK_DIR:-/tmp/pi-attach}
AUTH_FILE=${PI_AUTH_FILE:-$HOME/.pi/agent/auth.json}
MIRROR=nn-docker-remote.artifactory.insim.biz/library/node:22-slim

cmd_build() {
	# Stage build inputs into the context (kept out of git).
	mkdir -p "$PI_REPO/.pi-container/certs"
	cp /usr/local/share/ca-certificates/*.crt "$PI_REPO/.pi-container/certs/" 2>/dev/null || true
	# Fall back to the system bundle's certs if the dir was empty.
	if ! ls "$PI_REPO/.pi-container/certs"/*.crt >/dev/null 2>&1; then
		echo "no corp certs found in /usr/local/share/ca-certificates" >&2
		exit 1
	fi
	cp "$SCRIPT_DIR/settings.json" "$PI_REPO/.pi-container/settings.json"

	# Context hygiene (repo .dockerignore is generated, not committed).
	cat > "$PI_REPO/.dockerignore" <<'EOF'
.git
**/*.test.ts
**/test/
**/docs/
examples/
.github/
EOF
	docker --context default buildx build --builder default --load -f "$SCRIPT_DIR/Dockerfile" -t "$IMAGE" "$PI_REPO"
	rm -f "$PI_REPO/.dockerignore"
	echo "built $IMAGE"
}

cmd_run() {
	local project
	project=$(cd "${1:-.}" && pwd)
	mkdir -p "$SOCK_DIR"
	docker --context default rm -f "$NAME" >/dev/null 2>&1 || true
	docker --context default run -d --name "$NAME" \
		-v "$SOCK_DIR:/sock" \
		-v "$AUTH_FILE:/home/node/.pi/agent/auth.json" \
		-v "$project:/work" \
		-w /work \
		"$IMAGE" --mode rpc --sock /sock/agent.sock
	echo "agent container '$NAME' running; socket: $SOCK_DIR/agent.sock"
	echo "project mounted at /work: $project"
}

cmd_attach() {
	node "$PI_REPO/packages/coding-agent/dist/cli.js" attach --sock "$SOCK_DIR/agent.sock"
}

cmd_exec() {
	docker --context default exec -i "$NAME" node /opt/pi/packages/coding-agent/dist/cli.js --version >/dev/null
	node "$PI_REPO/packages/coding-agent/dist/cli.js" attach \
		--cmd "docker --context default exec -i $NAME node /opt/pi/packages/coding-agent/dist/cli.js --mode rpc"
}

cmd_stop() { docker --context default rm -f "$NAME"; }
cmd_logs() { docker --context default logs -f "$NAME"; }

case "${1:-}" in
	build) cmd_build ;;
	run) shift; cmd_run "$@" ;;
	attach) cmd_attach ;;
	exec) cmd_exec ;;
	stop) cmd_stop ;;
	logs) cmd_logs ;;
	*) grep '^#' "$0" | head -20; exit 1 ;;
esac
