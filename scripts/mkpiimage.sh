#!/bin/sh
# mkpiimage.sh — build the pi-agent image for `gantry pi`.
#
# Produces ./pi-agent.tar (a docker save tar, which gantry's image loader
# flattens and caches by digest). The image carries node + the pi coding
# agent + the basics pi shells out to (bash, git, ripgrep, certs). The
# guest arch must match the VM kernel — on Apple Silicon that's arm64.
#
#   ./scripts/mkpiimage.sh                 # → ./artifacts/pi-agent.tar
#   gantry pi -image ./artifacts/pi-agent.tar -secret ANTHROPIC_API_KEY
#
# Needs docker (or podman, via DOCKER=podman) with network access.
# apt/npm inside the build go through $PROXY (default below; override
# with PROXY=... or PROXY= to disable). NOTE: pulling the base image
# uses the docker DAEMON's own proxy config (~/.docker/config.json
# "proxies" or daemon env) — build-args can't affect that.
set -e
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ARTIFACTS=${GANTRY_ARTIFACTS:-$ROOT/artifacts}
mkdir -p "$ARTIFACTS"
cd "$ROOT"

DOCKER=${DOCKER:-docker}
PROXY=${PROXY:-http://192.168.1.1:3128}
PLATFORM=${PLATFORM:-linux/$(uname -m | sed 's/x86_64/amd64/;s/arm64/arm64/')}
OUT=${OUT:-$ARTIFACTS/pi-agent.tar}

proxy_args=""
if [ -n "$PROXY" ]; then
  # the predefined proxy build-args are passed to RUN steps as env vars
  # (and are not persisted into the image)
  proxy_args="--build-arg HTTP_PROXY=$PROXY --build-arg HTTPS_PROXY=$PROXY \
    --build-arg http_proxy=$PROXY --build-arg https_proxy=$PROXY \
    --build-arg NO_PROXY=localhost,127.0.0.1,::1 --build-arg no_proxy=localhost,127.0.0.1,::1"
fi

# shellcheck disable=SC2086
"$DOCKER" build --platform "$PLATFORM" $proxy_args -t pi-agent -f - . <<'EOF'
FROM node:24-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates git ripgrep \
 && rm -rf /var/lib/apt/lists/*
RUN npm install -g --ignore-scripts @earendil-works/pi-coding-agent
WORKDIR /workspace
ENTRYPOINT ["pi"]
EOF

"$DOCKER" save pi-agent -o "$OUT"
ls -lh "$OUT"

cat <<EOF
done. First run:

  gantry pi -image ./$OUT -secret ANTHROPIC_API_KEY

After that, plain 'gantry pi' reattaches while the sandbox is running
(it persists per project directory as pi-<dirname>).
EOF
