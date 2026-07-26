#!/bin/bash
# run-tests.sh — push a fresh gantry-linux-amd64 to the test instance
# and run test-battery.sh on it via SSM.
#   export GANTRY_TEST_IID=i-xxx   (from infra-up.sh)
#   sh scripts/aws-kvm/run-tests.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
HERE=scripts/aws-kvm

REGION="${REGION:-eu-west-1}"
export AWS_DEFAULT_REGION="$REGION"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
BUCKET="${BUCKET:-gantry-kvm-test-$ACCOUNT}"

echo "== building + uploading gantry-linux-amd64 =="
GOOS=linux GOARCH=amd64 go build -o /tmp/gantry-linux-amd64 .
aws s3 cp /tmp/gantry-linux-amd64 "s3://$BUCKET/gantry-linux-amd64" --quiet
URL=$(aws s3 presign "s3://$BUCKET/gantry-linux-amd64" --expires-in 7200)

echo "== running battery on ${GANTRY_TEST_IID:?export GANTRY_TEST_IID} =="
# The battery downloads this exact binary (retry loop) before testing.
{ echo "GANTRY_ASSET_URL='$URL'"; cat "$HERE/test-battery.sh"; } > /tmp/gantry-battery-run.sh
python3 "$HERE/ssm.py" /tmp/gantry-battery-run.sh "${1:-900}"
