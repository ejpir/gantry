#!/bin/bash
# stage-assets.sh — build the linux/amd64 gantry binary (+ x86_64 gVisor
# rootfs if missing) and upload all test assets to the staging bucket.
# Run from the repo root:  sh scripts/aws-kvm/stage-assets.sh
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
ARTIFACTS=${GANTRY_ARTIFACTS:-$ROOT/artifacts}
cd "$ROOT"

REGION="${REGION:-eu-west-1}"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
BUCKET="${BUCKET:-gantry-kvm-test-$ACCOUNT}"
export AWS_DEFAULT_REGION="$REGION"

echo "== building gantry-linux-amd64 =="
# Unpredictable path: a predictable /tmp name lets another local user
# pre-plant a symlink and redirect the build output over one of our files.
BIN=$(mktemp "${TMPDIR:-/tmp}/gantry-linux-amd64.XXXXXX")
trap 'rm -f -- "$BIN"' EXIT HUP INT TERM
GOOS=linux GOARCH=amd64 go build -o "$BIN" ./cmd/gantry

echo "== building gantry-guest-x86_64 (credential helper) =="
GBIN=$(mktemp "${TMPDIR:-/tmp}/gantry-guest-x86_64.XXXXXX")
trap 'rm -f -- "$BIN" "$GBIN"' EXIT HUP INT TERM
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o "$GBIN" ./cmd/gantry-guest
# Stage under its release-asset name so the upload key matches what
# guestasset.EnsureGuestTools expects on the instance.
cp "$GBIN" "$ARTIFACTS/gantry-guest-x86_64"

if [ ! -f "$ARTIFACTS/nerdbox-rootfs-gvisor-x86_64.erofs" ]; then
	echo "== building gVisor rootfs variant (x86_64) =="
	sh "$ROOT/scripts/mkrootfs-gvisor.sh" "$ARTIFACTS/nerdbox-rootfs-x86_64.erofs"
fi

echo "== uploading to s3://$BUCKET =="
for f in "$BIN" "$ARTIFACTS/gantry-guest-x86_64" "$ARTIFACTS/nerdbox-kernel-x86_64" "$ARTIFACTS/nerdbox-rootfs-x86_64.erofs" \
         "$ARTIFACTS/nerdbox-rootfs-gvisor-x86_64.erofs" "$ARTIFACTS/debian-bookworm-amd64.erofs" "$ARTIFACTS/rwlayer-amd64.ext4"; do
	[ -f "$f" ] || { echo "MISSING: $f" >&2; exit 1; }
	aws s3 cp "$f" "s3://$BUCKET/$(basename "$f")" --quiet &
done
wait
aws s3 ls "s3://$BUCKET" --human-readable
echo "staged."
