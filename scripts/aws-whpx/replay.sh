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
REMOTE_EXE=${GANTRY_TEST_EXE:-C:/gantry/gantry-field.exe}
BIN=$(mktemp "${TMPDIR:-/tmp}/gantry-windows-amd64.XXXXXX.exe")
trap 'rm -f -- "$BIN"' EXIT HUP INT TERM

cd "$ROOT"
echo "== build windows/amd64 =="
GOOS=windows GOARCH=amd64 go build -o "$BIN" ./cmd/gantry

echo "== stage s3://$BUCKET/$KEY =="
aws s3 cp "$BIN" "s3://$BUCKET/$KEY" --region "$REGION" --only-show-errors

echo "== download binary through a presigned S3 URL =="
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$INSTANCE" \
	--s3-download "$BUCKET" "$KEY" "$REMOTE_EXE" 600

echo "== replay WHPX isolation/share/network validation =="
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$INSTANCE" \
	scripts/aws-whpx/field-validation.ps1 900
