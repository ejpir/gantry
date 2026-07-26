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

echo "== running battery on ${GANTRY_TEST_IID:?export GANTRY_TEST_IID} =="
# Bootstrap /opt/gantry on the instance: presign every asset and emit a
# retry-loop download block (fresh instances have nothing; existing
# files are kept, the binary is always refreshed).
ASSETS="gantry-linux-amd64 nerdbox-kernel-x86_64 nerdbox-rootfs-x86_64.erofs nerdbox-rootfs-gvisor-x86_64.erofs debian-bookworm-amd64.erofs rwlayer-amd64.ext4"
DL="mkdir -p /opt/gantry && cd /opt/gantry"
for a in $ASSETS; do
	U=$(aws s3 presign "s3://$BUCKET/$a" --expires-in 7200)
	if [ "$a" = gantry-linux-amd64 ]; then
		# stop daemons first, then download to a temp name and mv
		# atomically: overwriting a RUNNING binary fails with
		# ETXTBSY (curl 23), which previously left a stale binary
		# testing the wrong code
		DL="$DL
pkill -f gantry-linux-amd64 2>/dev/null || true; sleep 1
for _ in 1 2 3 4 5; do curl -fSL --retry 3 -o gantry-new '$U' && break; sleep 3; done
mv -f gantry-new '$a' && chmod +x '$a'"
	else
		DL="$DL
[ -s '$a' ] || { for _ in 1 2 3 4 5; do curl -fSL --retry 3 -o '$a' '$U' && break; sleep 3; done; }"
	fi
done
SU=$(aws s3 presign "s3://$BUCKET/alpine-store.tar.gz" --expires_in 7200 2>/dev/null || aws s3 presign "s3://$BUCKET/alpine-store.tar.gz" --expires-in 7200)
{ echo "$DL"; echo "export GANTRY_STORE_URL='$SU'"; echo "ls -la /opt/gantry"; cat "$HERE/test-battery.sh"; } > /tmp/gantry-battery-run.sh
python3 "$HERE/ssm.py" /tmp/gantry-battery-run.sh "${1:-1200}"
