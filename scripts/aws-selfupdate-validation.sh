#!/bin/sh
# Build deliberately old tagged binaries, stage them through S3, and validate
# real in-place updates against the latest checksummed Gantry GitHub release.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
REGION=${GANTRY_TEST_REGION:-eu-west-1}
LINUX_IID=${GANTRY_LINUX_IID:?set GANTRY_LINUX_IID}
WINDOWS_IID=${GANTRY_WINDOWS_IID:?set GANTRY_WINDOWS_IID}
ACCOUNT=$(aws sts get-caller-identity --region "$REGION" --query Account --output text)
BUCKET=${GANTRY_TEST_BUCKET:-gantry-kvm-test-$ACCOUNT}
LINUX_KEY=${GANTRY_TEST_UPDATE_LINUX_KEY:-selfupdate/gantry-linux-amd64-v0.0.0}
WINDOWS_KEY=${GANTRY_TEST_UPDATE_WINDOWS_KEY:-selfupdate/gantry-windows-amd64-v0.0.0.exe}
LINUX_REMOTE=${GANTRY_TEST_UPDATE_LINUX_EXE:-/opt/gantry/gantry-self-update-test}
WINDOWS_REMOTE=${GANTRY_TEST_UPDATE_WINDOWS_EXE:-C:/gantry/gantry-self-update-test.exe}

LINUX_BIN=$(mktemp "${TMPDIR:-/tmp}/gantry-update-linux.XXXXXX")
WINDOWS_BIN=$(mktemp "${TMPDIR:-/tmp}/gantry-update-windows.XXXXXX.exe")
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	rm -f -- "$LINUX_BIN" "$WINDOWS_BIN"
	aws s3 rm "s3://$BUCKET/$LINUX_KEY" --region "$REGION" --only-show-errors >/dev/null 2>&1 || true
	aws s3 rm "s3://$BUCKET/$WINDOWS_KEY" --region "$REGION" --only-show-errors >/dev/null 2>&1 || true
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

LDFLAGS='-X github.com/ejpir/gantry/internal/guestasset.Version=v0.0.0'
echo "== build disposable v0.0.0 self-update binaries =="
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o "$LINUX_BIN" ./cmd/gantry
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o "$WINDOWS_BIN" ./cmd/gantry
aws s3 cp "$LINUX_BIN" "s3://$BUCKET/$LINUX_KEY" --region "$REGION" --only-show-errors
aws s3 cp "$WINDOWS_BIN" "s3://$BUCKET/$WINDOWS_KEY" --region "$REGION" --only-show-errors

echo "== stage disposable update targets =="
GANTRY_TEST_REGION=$REGION python3 scripts/aws-kvm/ssm.py "$LINUX_IID" \
	--s3-download "$BUCKET" "$LINUX_KEY" "$LINUX_REMOTE" 600
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$WINDOWS_IID" \
	--s3-download "$BUCKET" "$WINDOWS_KEY" "$WINDOWS_REMOTE" 600

echo "== Linux verified self-update =="
GANTRY_TEST_REGION=$REGION python3 scripts/aws-kvm/ssm.py "$LINUX_IID" \
	scripts/aws-kvm/self-update-validation.sh 900

echo "== Windows verified self-update =="
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$WINDOWS_IID" \
	scripts/aws-whpx/self-update-validation.ps1 900
