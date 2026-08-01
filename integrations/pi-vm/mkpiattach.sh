#!/bin/sh
# mkpiattach.sh — build the pi-attach agent image for gantry VMs.
#
# Packages a LOCAL pi checkout (the pi-attach-v1 branch, with `pi attach`
# + `--mode rpc --sock`) together with the guest bridge into a docker-save
# tar that `gantry run -image` / `gantry pi -image` load directly.
#
#   integrations/pi-vm/mkpiattach.sh              # → ./artifacts/pi-attach.tar
#   gantry pi -image ./artifacts/pi-attach.tar -serve # boot + serve
#   pi attach --cmd "gantry exec pi-<dir> -- node /opt/pi/bridge.js"
#
# Env:
#   PI_REPO   path to the pi checkout      (default: sibling ../pi)
#   DOCKER    docker/podman binary         (default: docker)
#   BASE      base image                   (default: node:24-bookworm-slim;
#             sandbox/corp: set the Artifactory mirror)
#   PROXY     build-time proxy             (default: none; corp sandbox:
#             http://gateway.docker.internal:3128, mac LAN:
#             http://192.168.1.1:3128)
#   REGISTRY  npm registry override        (default: npmjs via PROXY)
#   CA_DIR    dir of corp root .pem files  (default: ../pi-container/certs)
#   OUT       output tar                   (default: artifacts/pi-attach.tar)
set -e

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PI_REPO=${PI_REPO:-$(CDPATH= cd -- "$HERE/../../../pi" && pwd)}
DOCKER=${DOCKER:-docker}
# The kind/podman context defaults to a buildx container driver that pulls
# its boot image from Docker Hub (blocked); the default context's built-in
# builder works offline.
CLI="$DOCKER --context default"
BASE=${BASE:-node:24-bookworm-slim}
PROXY=${PROXY:-}
REGISTRY=${REGISTRY:-}
CA_DIR=${CA_DIR:-$HERE/../pi-container/certs}
OUT=${OUT:-$HERE/../../artifacts/pi-attach.tar}
mkdir -p "$(dirname -- "$OUT")"

[ -d "$PI_REPO/packages/coding-agent" ] || { echo "mkpiattach: PI_REPO $PI_REPO is not a pi checkout" >&2; exit 2; }

CTX=$(mktemp -d)
trap 'rm -rf "$CTX"' EXIT

# Stage the repo without host-built artifacts (the image rebuilds for the
# guest arch; node_modules from the host would be the wrong platform).
mkdir "$CTX/pi-repo"
tar -C "$PI_REPO" --exclude=node_modules --exclude=.git --exclude=dist -cf - . | tar -C "$CTX/pi-repo" -xf -
mkdir "$CTX/ca"
if [ -d "$CA_DIR" ]; then cp "$CA_DIR"/*.pem "$CTX/ca/" 2>/dev/null || true; fi
cp "$HERE/Dockerfile" "$CTX/Dockerfile"
cp "$HERE/bridge.js" "$CTX/bridge.js"

args="--build-arg BASE=$BASE"
if [ -n "$PROXY" ]; then
  args="$args --build-arg HTTP_PROXY=$PROXY --build-arg HTTPS_PROXY=$PROXY"
fi
if [ -n "$REGISTRY" ]; then
  args="$args --build-arg REGISTRY=$REGISTRY"
fi

# --builder default: the buildx docker-container driver boots a buildkit
# image from Docker Hub (Zscaler-blocked here); the daemon's built-in
# builder needs no boot image. --load puts the result into docker images.
# shellcheck disable=SC2086
$CLI build --builder default --load $args -t pi-attach-agent "$CTX"
$CLI save -o "$OUT" pi-attach-agent
echo "mkpiattach: wrote $OUT ($(du -h "$OUT" | cut -f1))"
