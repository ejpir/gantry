#!/bin/bash
# stage-assets.sh — build the linux/amd64 gantry binary (+ x86_64 gVisor
# rootfs if missing) and upload all test assets to the staging bucket.
# Run from the repo root:  sh scripts/aws-kvm/stage-assets.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

REGION="${REGION:-eu-west-1}"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
BUCKET="${BUCKET:-gantry-kvm-test-$ACCOUNT}"
export AWS_DEFAULT_REGION="$REGION"

echo "== building gantry-linux-amd64 =="
GOOS=linux GOARCH=amd64 go build -o /tmp/gantry-linux-amd64 .

if [ ! -f nerdbox-rootfs-gvisor-x86_64.erofs ]; then
	echo "== building gVisor rootfs variant (x86_64) =="
	sh mkrootfs-gvisor.sh nerdbox-rootfs-x86_64.erofs
fi

echo "== uploading to s3://$BUCKET =="
for f in /tmp/gantry-linux-amd64 nerdbox-kernel-x86_64 nerdbox-rootfs-x86_64.erofs \
         nerdbox-rootfs-gvisor-x86_64.erofs debian-bookworm-amd64.erofs rwlayer-amd64.ext4; do
	[ -f "$f" ] || { echo "MISSING: $f" >&2; exit 1; }
	aws s3 cp "$f" "s3://$BUCKET/$(basename "$f")" --quiet &
done
wait
aws s3 ls "s3://$BUCKET" --human-readable
echo "staged."
