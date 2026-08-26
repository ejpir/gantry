#!/bin/sh
# Run the complete AWS x86_64 field validation on the repository's reusable
# Linux KVM and Windows WHPX hosts. The script starts stopped instances, waits
# for SSM, stages fresh binaries, runs every maintained battery, and stops the
# hosts on exit unless GANTRY_KEEP_INSTANCES=1.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

KEYS_FILE=${GANTRY_KEYS_FILE:-$HOME/keys}
if [ -z "${AWS_ACCESS_KEY_ID:-}" ] && [ -f "$KEYS_FILE" ]; then
	set -a
	# shellcheck disable=SC1090
	. "$KEYS_FILE"
	set +a
fi

REGION=${GANTRY_TEST_REGION:-eu-west-1}
export AWS_DEFAULT_REGION=$REGION
ACCOUNT=$(aws sts get-caller-identity --region "$REGION" --query Account --output text)
BUCKET=${GANTRY_TEST_BUCKET:-gantry-kvm-test-$ACCOUNT}

instance_by_name() {
	name=$1
	aws ec2 describe-instances --region "$REGION" \
		--filters "Name=tag:Name,Values=$name" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
		--query 'Reservations[].Instances[].InstanceId' --output text | awk '{print $1}'
}

LINUX_IID=${GANTRY_LINUX_IID:-$(instance_by_name gantry-kvm-test)}
WINDOWS_IID=${GANTRY_WINDOWS_IID:-$(instance_by_name gantry-whpx-test)}
[ -n "$LINUX_IID" ] || { echo "Linux KVM instance not found (set GANTRY_LINUX_IID)" >&2; exit 1; }
[ -n "$WINDOWS_IID" ] || { echo "Windows WHPX instance not found (set GANTRY_WINDOWS_IID)" >&2; exit 1; }

DIRECTORY_RUN=
IDE_BUILD_DIR=
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	[ -z "$DIRECTORY_RUN" ] || rm -f -- "$DIRECTORY_RUN"
	[ -z "$IDE_BUILD_DIR" ] || rm -rf -- "$IDE_BUILD_DIR"
	if [ "${GANTRY_KEEP_INSTANCES:-0}" != 1 ]; then
		echo "== stopping AWS validation instances =="
		aws ec2 stop-instances --region "$REGION" \
			--instance-ids "$LINUX_IID" "$WINDOWS_IID" >/dev/null 2>&1 || true
	else
		echo "== GANTRY_KEEP_INSTANCES=1: leaving instances running =="
	fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

# Build the curated x86_64 image from the current Dockerfile so the field run
# validates these source changes rather than a stale release or S3 object. A
# caller may provide an already-built image when replaying in an air-gapped
# environment.
IDE_IMAGE=${GANTRY_TEST_IDE_IMAGE:-}
if [ -z "$IDE_IMAGE" ]; then
	IDE_BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/gantry-ide-x86_64.XXXXXX")
	IDE_IMAGE=$IDE_BUILD_DIR/gantry-ide-image-x86_64.erofs
	sh scripts/mkideimage.sh "$IDE_IMAGE" linux/amd64
fi
[ -s "$IDE_IMAGE" ] || { echo "curated IDE image missing: $IDE_IMAGE" >&2; exit 1; }
echo "== staging current curated IDE image =="
aws s3 cp "$IDE_IMAGE" "s3://$BUCKET/gantry-ide-image-x86_64.erofs" \
	--region "$REGION" --only-show-errors

instance_state() {
	aws ec2 describe-instances --region "$REGION" --instance-ids "$1" \
		--query 'Reservations[0].Instances[0].State.Name' --output text
}

wait_instance_state() {
	iid=$1
	wanted=$2
	# Bare-metal Windows shutdown can exceed the AWS CLI waiter's ten-minute
	# ceiling. Poll for up to an hour so a previous cleanup does not make the
	# next validation fail while EC2 is still draining the host.
	attempt=0
	while [ "$attempt" -lt 240 ]; do
		state=$(instance_state "$iid")
		[ "$state" = "$wanted" ] && return 0
		attempt=$((attempt + 1))
		sleep 15
	done
	echo "$iid did not reach $wanted (current state: $(instance_state "$iid"))" >&2
	return 1
}

start_instance() {
	iid=$1
	state=$(instance_state "$iid")
	if [ "$state" = stopping ]; then
		wait_instance_state "$iid" stopped
		state=stopped
	fi
	if [ "$state" = stopped ]; then
		aws ec2 start-instances --region "$REGION" --instance-ids "$iid" >/dev/null
	fi
	wait_instance_state "$iid" running
}

wait_ssm() {
	iid=$1
	attempt=0
	while [ "$attempt" -lt 60 ]; do
		status=$(aws ssm describe-instance-information --region "$REGION" \
			--filters "Key=InstanceIds,Values=$iid" \
			--query 'InstanceInformationList[0].PingStatus' --output text)
		[ "$status" = Online ] && return 0
		attempt=$((attempt + 1))
		sleep 10
	done
	echo "SSM did not become online for $iid" >&2
	return 1
}

echo "== starting AWS validation instances =="
start_instance "$LINUX_IID"
start_instance "$WINDOWS_IID"
wait_ssm "$LINUX_IID"
wait_ssm "$WINDOWS_IID"

if [ "${GANTRY_SKIP_SELFUPDATE:-0}" = 1 ]; then
	echo "===== Linux + Windows: self-update battery skipped by GANTRY_SKIP_SELFUPDATE ====="
else
	echo "===== Linux + Windows: verified self-update battery ====="
	GANTRY_LINUX_IID=$LINUX_IID GANTRY_WINDOWS_IID=$WINDOWS_IID \
		GANTRY_TEST_BUCKET=$BUCKET GANTRY_TEST_REGION=$REGION \
		sh scripts/aws-selfupdate-validation.sh
fi

echo "===== Windows WHPX: field + security + SSH/Dev Containers + directory batteries ====="
GANTRY_TEST_IID=$WINDOWS_IID GANTRY_TEST_BUCKET=$BUCKET \
	GANTRY_TEST_REGION=$REGION sh scripts/aws-whpx/replay.sh

echo "===== Linux KVM: main field battery ====="
GANTRY_TEST_IID=$LINUX_IID BUCKET=$BUCKET REGION=$REGION \
	sh scripts/aws-kvm/run-tests.sh 1800

echo "===== Linux KVM: SSH/Dev Containers battery ====="
GANTRY_TEST_IID=$LINUX_IID GANTRY_TEST_REGION=$REGION \
	python3 scripts/aws-kvm/ssm.py scripts/aws-kvm/ssh-devcontainers-validation.sh 1800

echo "===== Linux KVM: large-directory battery ====="
DIRECTORY_RUN=$(mktemp "${TMPDIR:-/tmp}/gantry-linux-directory.XXXXXX.sh")
{
	cat <<'EOF'
export GANTRY_TEST_EXE=/opt/gantry/gantry-linux-amd64
export GANTRY_TEST_KERNEL=/opt/gantry/nerdbox-kernel-x86_64
export GANTRY_TEST_ROOTFS=/opt/gantry/nerdbox-rootfs-x86_64.erofs
export GANTRY_TEST_IMAGE=/opt/gantry/debian-bookworm-amd64.erofs
export GANTRY_TEST_SANDBOX=dirscan-x86_64-current
export GANTRY_HOME=/opt/gantry/state-directory
EOF
	cat scripts/aws-kvm/directory-validation.sh
} >"$DIRECTORY_RUN"
GANTRY_TEST_IID=$LINUX_IID GANTRY_TEST_REGION=$REGION \
	python3 scripts/aws-kvm/ssm.py "$DIRECTORY_RUN" 2400
rm -f -- "$DIRECTORY_RUN"
DIRECTORY_RUN=

echo "===== Linux KVM: required-confinement battery ====="
GANTRY_TEST_IID=$LINUX_IID GANTRY_TEST_REGION=$REGION \
	python3 scripts/aws-kvm/ssm.py scripts/aws-kvm/confinement-battery.sh 1200

echo "===== AWS E2E VALIDATION PASSED ====="
