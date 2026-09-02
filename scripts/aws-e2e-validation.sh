#!/bin/sh
# Run the complete field validation. With no arguments this drives the
# repository's reusable AWS Linux KVM and Windows WHPX hosts. `macos` instead
# runs the maintained cross-platform batteries locally on Apple silicon HVF
# without loading AWS credentials or touching EC2 instances.
#
#   sh scripts/aws-e2e-validation.sh          # AWS Linux + Windows
#   sh scripts/aws-e2e-validation.sh macos    # local Apple-silicon macOS
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

usage() {
	cat <<'EOF'
usage: scripts/aws-e2e-validation.sh [aws|macos]

  aws      validate the reusable AWS Linux KVM and Windows WHPX hosts (default)
  macos    validate the local Apple-silicon macOS HVF backend

macOS overrides:
  GANTRY_ARTIFACTS               artifact directory (default: ./artifacts)
  GANTRY_TEST_KERNEL             arm64 guest kernel
  GANTRY_TEST_ROOTFS             arm64 Nerdbox rootfs
  GANTRY_TEST_WORKLOAD_IMAGE     workload EROFS image (default: downloaded test image)
  GANTRY_TEST_IDE_IMAGE          curated Dev Containers EROFS image
  GANTRY_SKIP_DEVCONTAINERS=1    skip SSH/Dev Containers and directory batteries
EOF
}

MODE=${GANTRY_E2E_TARGET:-aws}
if [ "$#" -gt 1 ]; then
	usage >&2
	exit 2
fi
if [ "$#" -eq 1 ]; then
	case "$1" in
	aws|--aws) MODE=aws ;;
	macos|darwin|--macos) MODE=macos ;;
	-h|--help) usage; exit 0 ;;
	*) usage >&2; exit 2 ;;
	esac
fi

run_macos_validation() {
	[ "$(uname -s)" = Darwin ] || {
		echo "macos validation must run on macOS" >&2
		exit 1
	}
	case $(uname -m) in
	arm64|aarch64) ;;
	*) echo "macos validation requires Apple silicon (found $(uname -m))" >&2; exit 1 ;;
	esac
	for command_name in go codesign python3 ssh sftp; do
		command -v "$command_name" >/dev/null 2>&1 || {
			echo "required command not found: $command_name" >&2
			exit 1
		}
	done
	[ -n "${HOME:-}" ] || { echo "HOME must be set for macOS validation" >&2; exit 1; }

	# Keep Unix-domain endpoints below Darwin's 104-byte sockaddr_un limit.
	MAC_TMP=$(mktemp -d /tmp/gantry-me2e.XXXXXX)
	MAC_ARTIFACTS=${GANTRY_ARTIFACTS:-$ROOT/artifacts}
	mkdir -p "$MAC_ARTIFACTS"
	MAC_ARTIFACTS=$(CDPATH= cd -- "$MAC_ARTIFACTS" && pwd)
	cleanup_macos() {
		status=$?
		trap - EXIT HUP INT TERM
		rm -rf -- "$MAC_TMP"
		exit "$status"
	}
	trap cleanup_macos EXIT
	trap 'exit 130' HUP INT TERM

	echo "===== macOS HVF: build and sign current host/guest binaries ====="
	GANTRY_ARTIFACTS="$MAC_ARTIFACTS" sh scripts/build.sh
	MAC_GANTRY=$MAC_ARTIFACTS/gantry-darwin-arm64
	MAC_GUEST=$MAC_ARTIFACTS/gantry-guest-arm64
	[ -x "$MAC_GANTRY" ] || { echo "missing host binary: $MAC_GANTRY" >&2; exit 1; }
	[ -s "$MAC_GUEST" ] || { echo "missing guest helper: $MAC_GUEST" >&2; exit 1; }

	MAC_KERNEL=${GANTRY_TEST_KERNEL:-$MAC_ARTIFACTS/gantry-kernel-arm64}
	MAC_ROOTFS=${GANTRY_TEST_ROOTFS:-$MAC_ARTIFACTS/nerdbox-rootfs-arm64.erofs}
	MAC_WORKLOAD=${GANTRY_TEST_WORKLOAD_IMAGE:-builtin}
	echo "===== macOS HVF: manager API lifecycle battery ====="
	GANTRY_ARTIFACTS="$MAC_ARTIFACTS" sh scripts/test-manager-api-e2e.sh \
		-gantry "$MAC_GANTRY" \
		-artifacts "$MAC_ARTIFACTS" \
		-kernel "$MAC_KERNEL" \
		-rootfs "$MAC_ROOTFS" \
		-image "$MAC_WORKLOAD" \
		-work-dir "$MAC_TMP/manager"
	if [ "$MAC_WORKLOAD" = builtin ]; then
		MAC_WORKLOAD=$HOME/Library/Caches/gantry/e2e-assets/gantry-default-image-arm64.erofs
	fi
	[ -s "$MAC_WORKLOAD" ] || {
		echo "macOS workload image missing after manager battery: $MAC_WORKLOAD" >&2
		exit 1
	}

	echo "===== macOS HVF: credential-broker battery ====="
	GANTRY_ARTIFACTS="$MAC_ARTIFACTS" \
		GANTRY_TEST_EXE="$MAC_GANTRY" \
		GANTRY_TEST_GUEST="$MAC_GUEST" \
		IMAGE="$MAC_WORKLOAD" \
		bash scripts/test-credhelper-local.sh

	if [ "${GANTRY_SKIP_DEVCONTAINERS:-0}" = 1 ]; then
		echo "===== macOS HVF: SSH/Dev Containers and directory batteries skipped ====="
	else
		MAC_IDE_IMAGE=${GANTRY_TEST_IDE_IMAGE:-}
		if [ -z "$MAC_IDE_IMAGE" ] && [ -s "$MAC_ARTIFACTS/gantry-ide-image-arm64.erofs" ]; then
			MAC_IDE_IMAGE=$MAC_ARTIFACTS/gantry-ide-image-arm64.erofs
		fi
		if [ -z "$MAC_IDE_IMAGE" ]; then
			for command_name in docker mkfs.erofs; do
				command -v "$command_name" >/dev/null 2>&1 || {
					echo "required to build the curated IDE image: $command_name" >&2
					echo "set GANTRY_TEST_IDE_IMAGE or GANTRY_SKIP_DEVCONTAINERS=1 to continue without building it" >&2
					exit 1
				}
			done
			MAC_IDE_IMAGE=$MAC_TMP/gantry-ide-image-arm64.erofs
			echo "===== macOS HVF: build current curated IDE image ====="
			sh scripts/mkideimage.sh "$MAC_IDE_IMAGE" linux/arm64
		fi
		[ -s "$MAC_IDE_IMAGE" ] || { echo "curated IDE image missing: $MAC_IDE_IMAGE" >&2; exit 1; }

		# Default Dev Containers resolution uses a canonical basename below
		# GANTRY_ARTIFACTS. Stage regular files in the private test tree so a
		# caller-provided image is the image actually exercised, without
		# overwriting the caller's artifact directory.
		MAC_FIELD_ASSETS=$MAC_TMP/field-assets
		mkdir -p "$MAC_FIELD_ASSETS"
		stage_macos_asset() {
			source_path=$1
			destination_path=$2
			ln "$source_path" "$destination_path" 2>/dev/null || cp "$source_path" "$destination_path"
		}
		stage_macos_asset "$MAC_IDE_IMAGE" "$MAC_FIELD_ASSETS/gantry-ide-image-arm64.erofs"
		stage_macos_asset "$MAC_GUEST" "$MAC_FIELD_ASSETS/gantry-guest-arm64"
		MAC_IDE_IMAGE=$MAC_FIELD_ASSETS/gantry-ide-image-arm64.erofs

		for required_path in "$MAC_KERNEL" "$MAC_ROOTFS"; do
			[ -s "$required_path" ] || { echo "required guest asset missing: $required_path" >&2; exit 1; }
		done

		echo "===== macOS HVF: SSH/Dev Containers battery ====="
		GANTRY_TEST_ROOT="$MAC_FIELD_ASSETS" \
			GANTRY_TEST_EXE="$MAC_GANTRY" \
			GANTRY_TEST_KERNEL="$MAC_KERNEL" \
			GANTRY_TEST_ROOTFS="$MAC_ROOTFS" \
			GANTRY_TEST_IDE_IMAGE="$MAC_IDE_IMAGE" \
			GANTRY_TEST_WORKLOAD_IMAGE="$MAC_WORKLOAD" \
			GANTRY_TEST_GUEST="$MAC_GUEST" \
			GANTRY_TEST_SANDBOX=ssh-devcontainers-hvf \
			GANTRY_TEST_PLATFORM='macOS HVF' \
			GANTRY_HOME="$MAC_TMP/ssh/sandboxes" \
			bash scripts/aws-kvm/ssh-devcontainers-validation.sh

		echo "===== macOS HVF: large-directory battery ====="
		GANTRY_TEST_ARCH=arm64 \
			GANTRY_TEST_ROOT="$MAC_FIELD_ASSETS" \
			GANTRY_TEST_EXE="$MAC_GANTRY" \
			GANTRY_TEST_KERNEL="$MAC_KERNEL" \
			GANTRY_TEST_ROOTFS="$MAC_ROOTFS" \
			GANTRY_TEST_IMAGE="$MAC_IDE_IMAGE" \
			GANTRY_TEST_GUEST_DIR=/home/gantry/gantry-dirscan \
			GANTRY_TEST_SANDBOX=dirscan-arm64-hvf \
			GANTRY_HOME="$MAC_TMP/directory/sandboxes" \
			sh scripts/aws-kvm/directory-validation.sh
	fi

	echo "===== macOS E2E VALIDATION PASSED ====="
}

case "$MODE" in
aws) ;;
macos) run_macos_validation; exit 0 ;;
*) echo "unknown GANTRY_E2E_TARGET: $MODE" >&2; usage >&2; exit 2 ;;
esac

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
