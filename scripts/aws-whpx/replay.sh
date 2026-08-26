#!/bin/sh
# Build, stage, and replay the Windows WHPX field validation through SSM.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
REGION=${GANTRY_TEST_REGION:-eu-west-1}
INSTANCE=${GANTRY_TEST_IID:?set GANTRY_TEST_IID to the Windows metal instance id}

if [ -z "${AWS_ACCESS_KEY_ID:-}" ] && [ -f "${GANTRY_KEYS_FILE:-$HOME/keys}" ]; then
	# shellcheck disable=SC1090
	. "${GANTRY_KEYS_FILE:-$HOME/keys}"
fi

ACCOUNT=$(aws sts get-caller-identity --region "$REGION" --query Account --output text)
BUCKET=${GANTRY_TEST_BUCKET:-gantry-kvm-test-$ACCOUNT}
KEY=${GANTRY_TEST_BINARY_KEY:-whpx/gantry-field.exe}
GUEST_KEY=${GANTRY_TEST_GUEST_KEY:-whpx/gantry-guest-x86_64}
IDE_KEY=${GANTRY_TEST_IDE_KEY:-gantry-ide-image-x86_64.erofs}
KERNEL_KEY=${GANTRY_TEST_KERNEL_KEY:-gantry-kernel-x86_64}
ROOTFS_KEY=${GANTRY_TEST_ROOTFS_KEY:-nerdbox-rootfs-x86_64.erofs}
REMOTE_EXE=${GANTRY_TEST_EXE:-C:/gantry/gantry-field.exe}
REMOTE_GUEST=${GANTRY_TEST_GUEST:-C:/gantry/gantry-guest-x86_64}
REMOTE_IDE=${GANTRY_TEST_REMOTE_IDE_IMAGE:-C:/gantry/gantry-ide-image-x86_64.erofs}
REMOTE_KERNEL=${GANTRY_TEST_CURRENT_KERNEL:-C:/gantry/gantry-kernel-x86_64}
REMOTE_ROOTFS=${GANTRY_TEST_CURRENT_ROOTFS:-C:/gantry/nerdbox-rootfs-x86_64.erofs}
BIN=$(mktemp "${TMPDIR:-/tmp}/gantry-windows-amd64.XXXXXX.exe")
GBIN=$(mktemp "${TMPDIR:-/tmp}/gantry-guest-x86_64.XXXXXX")
trap 'rm -f -- "$BIN" "$GBIN"' EXIT HUP INT TERM

cd "$ROOT"
echo "== build windows/amd64 host + linux/amd64 guest helper =="
GOOS=windows GOARCH=amd64 go build -o "$BIN" ./cmd/gantry
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o "$GBIN" ./cmd/gantry-guest

echo "== stage s3://$BUCKET/$KEY and $GUEST_KEY =="
aws s3 cp "$BIN" "s3://$BUCKET/$KEY" --region "$REGION" --only-show-errors
aws s3 cp "$GBIN" "s3://$BUCKET/$GUEST_KEY" --region "$REGION" --only-show-errors

echo "== stop stale field daemons and download binaries through presigned S3 URLs =="
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$INSTANCE" -c \
	"Get-Process -Name gantry-field -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep -Seconds 1" 120
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$INSTANCE" \
	--s3-download "$BUCKET" "$KEY" "$REMOTE_EXE" 600
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$INSTANCE" \
	--s3-download "$BUCKET" "$GUEST_KEY" "$REMOTE_GUEST" 600
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$INSTANCE" \
	--s3-download "$BUCKET" "$IDE_KEY" "$REMOTE_IDE" 900
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$INSTANCE" \
	--s3-download "$BUCKET" "$KERNEL_KEY" "$REMOTE_KERNEL" 900
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$INSTANCE" \
	--s3-download "$BUCKET" "$ROOTFS_KEY" "$REMOTE_ROOTFS" 900

echo "== replay WHPX SSH/Dev Containers validation =="
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$INSTANCE" \
	scripts/aws-whpx/ssh-devcontainers-validation.ps1 1800

if [ "${GANTRY_WHPX_ONLY_SSH_DEVCONTAINERS:-0}" = 1 ]; then
	echo "== GANTRY_WHPX_ONLY_SSH_DEVCONTAINERS=1: focused replay complete =="
	exit 0
fi

echo "== replay WHPX isolation/share/network validation =="
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$INSTANCE" \
	scripts/aws-whpx/field-validation.ps1 900

echo "== replay WHPX secrets/OAuth/MCP validation =="
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$INSTANCE" \
	scripts/aws-whpx/security-validation.ps1 1200

echo "== replay WHPX large-directory validation =="
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$INSTANCE" \
	scripts/aws-whpx/directory-validation.ps1 2400
