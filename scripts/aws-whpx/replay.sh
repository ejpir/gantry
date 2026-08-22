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
REMOTE_EXE=${GANTRY_TEST_EXE:-C:/gantry/gantry-field.exe}
REMOTE_GUEST=${GANTRY_TEST_GUEST:-C:/gantry/gantry-guest-x86_64}
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

echo "== download binaries through presigned S3 URLs =="
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$INSTANCE" \
	--s3-download "$BUCKET" "$KEY" "$REMOTE_EXE" 600
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$INSTANCE" \
	--s3-download "$BUCKET" "$GUEST_KEY" "$REMOTE_GUEST" 600

echo "== replay WHPX isolation/share/network validation =="
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$INSTANCE" \
	scripts/aws-whpx/field-validation.ps1 900

echo "== replay WHPX secrets/OAuth/MCP validation =="
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$INSTANCE" \
	scripts/aws-whpx/security-validation.ps1 1200

echo "== replay WHPX large-directory validation =="
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$INSTANCE" \
	scripts/aws-whpx/directory-validation.ps1 2400
