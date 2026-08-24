#!/bin/bash
# Build the current Linux/ARM64 binaries, stage the ARM boot assets, and run
# the maintained KVM confinement/share/MCP battery on the Graviton host.
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
HERE="$ROOT/scripts/aws-kvm"

REGION="${REGION:-${GANTRY_TEST_REGION:-eu-west-1}}"
export AWS_DEFAULT_REGION="$REGION"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
BUCKET="${BUCKET:-gantry-kvm-test-$ACCOUNT}"
IID="${GANTRY_TEST_IID:?export GANTRY_TEST_IID for the ARM64 KVM host}"
ARTIFACTS="${GANTRY_ARTIFACTS:-$ROOT/artifacts}"

BIN=$(mktemp "${TMPDIR:-/tmp}/gantry-linux-arm64.XXXXXX")
GUEST=$(mktemp "${TMPDIR:-/tmp}/gantry-guest-arm64.XXXXXX")
RUN=$(mktemp "${TMPDIR:-/tmp}/gantry-arm64-battery.XXXXXX.sh")
trap 'rm -f -- "$BIN" "$GUEST" "$RUN"' EXIT HUP INT TERM

echo "== building current linux/arm64 binaries =="
GOOS=linux GOARCH=arm64 go build -o "$BIN" ./cmd/gantry
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w" -o "$GUEST" ./cmd/gantry-guest

KERNEL="$ARTIFACTS/gantry-kernel-arm64"
ROOTFS="$ARTIFACTS/nerdbox-rootfs-arm64.erofs"
[ -s "$KERNEL" ] || { echo "missing ARM64 kernel: $KERNEL" >&2; exit 1; }
[ -s "$ROOTFS" ] || { echo "missing ARM64 rootfs: $ROOTFS" >&2; exit 1; }
# The large Ubuntu test image is retained in the shared field-test bucket.
aws s3api head-object --bucket "$BUCKET" --key ubuntu-arm64.erofs >/dev/null

echo "== uploading current ARM64 test artifacts =="
aws s3 cp "$BIN" "s3://$BUCKET/gantry-linux-arm64-current" --quiet
aws s3 cp "$GUEST" "s3://$BUCKET/gantry-guest-arm64" --quiet
aws s3 cp "$KERNEL" "s3://$BUCKET/gantry-kernel-arm64" --quiet
aws s3 cp "$ROOTFS" "s3://$BUCKET/nerdbox-rootfs-arm64.erofs" --quiet

DL='mkdir -p /opt/gantry && cd /opt/gantry'
for asset in gantry-linux-arm64-current gantry-guest-arm64 gantry-kernel-arm64 nerdbox-rootfs-arm64.erofs ubuntu-arm64.erofs; do
	url=$(aws s3 presign "s3://$BUCKET/$asset" --expires-in 7200)
	case "$asset" in
	gantry-linux-arm64-current|gantry-guest-arm64|gantry-kernel-arm64|nerdbox-rootfs-arm64.erofs)
		DL="$DL
for _ in 1 2 3 4 5; do curl -fSL --retry 3 -o '$asset.new' '$url' && break; sleep 3; done
mv -f '$asset.new' '$asset'"
		;;
	ubuntu-arm64.erofs)
		DL="$DL
[ -s '$asset' ] || { for _ in 1 2 3 4 5; do curl -fSL --retry 3 -o '$asset.new' '$url' && break; sleep 3; done; mv -f '$asset.new' '$asset'; }"
		;;
	esac
done
DL="$DL
chmod 755 gantry-linux-arm64-current gantry-guest-arm64"

{
	echo "$DL"
	cat <<'EOF'
export GANTRY_TEST_EXE=/opt/gantry/gantry-linux-arm64-current
export GANTRY_TEST_KERNEL=/opt/gantry/gantry-kernel-arm64
export GANTRY_TEST_ROOTFS=/opt/gantry/nerdbox-rootfs-arm64.erofs
export GANTRY_TEST_IMAGE=/opt/gantry/ubuntu-arm64.erofs
export GANTRY_TEST_ARCH=aarch64
export GANTRY_HOME=/tmp/.gantry-arm64-current/sandboxes
export GANTRY_IMAGES=/tmp/.gantry-arm64-current/images
EOF
	cat "$HERE/confinement-battery.sh"
} >"$RUN"

echo "== running current ARM64 KVM battery on $IID =="
GANTRY_TEST_REGION="$REGION" python3 "$HERE/ssm.py" "$IID" "$RUN" "${1:-1200}"
