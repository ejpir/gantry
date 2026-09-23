#!/bin/sh
# Run the complete field validation. With no arguments this drives the
# repository's reusable AWS Linux amd64/arm64 KVM and Windows WHPX hosts.
# `linux` and `macos` run the maintained local batteries on KVM and Apple
# silicon HVF respectively (including Linux KVM on GitHub-hosted CI).
#
#   sh scripts/aws-e2e-validation.sh          # AWS Linux + Windows
#   sh scripts/aws-e2e-validation.sh linux    # local Linux KVM / CI
#   sh scripts/aws-e2e-validation.sh macos    # local Apple-silicon macOS
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

usage() {
	cat <<'EOF'
usage: scripts/aws-e2e-validation.sh [aws|linux|macos]

  aws      validate AWS Linux amd64/arm64 KVM and Windows WHPX hosts (default)
  linux    validate the local Linux KVM backend
  macos    validate the local Apple-silicon macOS HVF backend

All modes include signed OPA policy validation with real VMs and loopback-only
fixtures (no OPA/OpenSSL installation or public egress needed on test hosts).

Linux overrides:
  GANTRY_ARTIFACTS               guest-helper directory (default: ./artifacts)
  GANTRY_TEST_EXE                native Gantry executable
  GANTRY_TEST_KERNEL             guest kernel for the host architecture
  GANTRY_TEST_ROOTFS             matching Nerdbox rootfs
  GANTRY_TEST_WORKLOAD_IMAGE     local workload EROFS image
  GANTRY_TEST_RUNSC_KERNEL       optional gVisor-capable guest kernel
  GANTRY_TEST_RUNSC_ROOTFS       optional matching gVisor Nerdbox rootfs
  GANTRY_TEST_OAUTH_IDP          prebuilt disposable OAuth fixture
  GANTRY_TEST_IDE_IMAGE          curated Dev Containers EROFS image
  GANTRY_TEST_PUBLIC_EGRESS      required or skip (default: probe host capability)
  GANTRY_SKIP_DEVCONTAINERS=1    skip SSH/Dev Containers and directory batteries
  GANTRY_E2E_WORK_DIR            retained test workspace

macOS overrides:
  GANTRY_ARTIFACTS               artifact directory (default: ./artifacts)
  GANTRY_TEST_KERNEL             arm64 guest kernel
  GANTRY_TEST_ROOTFS             arm64 Nerdbox rootfs
  GANTRY_TEST_WORKLOAD_IMAGE     workload EROFS image (default: downloaded test image)
  GANTRY_TEST_IDE_IMAGE          curated Dev Containers EROFS image
  GANTRY_TEST_PUBLIC_EGRESS      required or skip (default: probe host capability)
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
	linux|--linux) MODE=linux ;;
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
	for command_name in go codesign python3 curl perl ssh sftp; do
		command -v "$command_name" >/dev/null 2>&1 || {
			echo "required command not found: $command_name" >&2
			exit 1
		}
	done
	[ -n "${HOME:-}" ] || { echo "HOME must be set for macOS validation" >&2; exit 1; }

	# The field battery normally requires direct public TCP egress. Corporate
	# macOS hosts may expose the Internet only through an application proxy,
	# which is a host-policy limitation rather than a Gantry failure. Probe the
	# exact direct endpoint without consulting proxy variables; callers can set
	# GANTRY_TEST_PUBLIC_EGRESS=required to force the assertion.
	MAC_PUBLIC_EGRESS=${GANTRY_TEST_PUBLIC_EGRESS:-}
	if [ -z "$MAC_PUBLIC_EGRESS" ]; then
		if python3 -c 'import socket; s = socket.create_connection(("1.1.1.1", 443), 5); s.close()' \
			>/dev/null 2>&1; then
			MAC_PUBLIC_EGRESS=required
		else
			MAC_PUBLIC_EGRESS=skip
			echo "macOS host has no direct public TCP path; public guest egress checks will be skipped" >&2
		fi
	fi

	# Keep Unix-domain endpoints below Darwin's 104-byte sockaddr_un limit.
	MAC_TMP=$(mktemp -d /tmp/gantry-me2e.XXXXXX)
	MAC_ARTIFACTS=${GANTRY_ARTIFACTS:-$ROOT/artifacts}
	mkdir -p "$MAC_ARTIFACTS"
	MAC_ARTIFACTS=$(CDPATH='' cd -- "$MAC_ARTIFACTS" && pwd)
	# shellcheck disable=SC2317 # Called indirectly by the EXIT trap.
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
	MAC_OAUTH_IDP=$MAC_TMP/gantry-oauth-idp
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build \
		-o "$MAC_OAUTH_IDP" ./tests/e2e/oauthidp
	codesign --force --sign - "$MAC_OAUTH_IDP"

	MAC_KERNEL=${GANTRY_TEST_KERNEL:-$MAC_ARTIFACTS/gantry-kernel-arm64}
	MAC_ROOTFS=${GANTRY_TEST_ROOTFS:-$MAC_ARTIFACTS/nerdbox-rootfs-arm64.erofs}
	MAC_WORKLOAD=${GANTRY_TEST_WORKLOAD_IMAGE:-builtin}
	echo "===== macOS HVF: manager API, remote dashboard parity, and lifecycle battery ====="
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

	echo "===== macOS HVF: core CLI, networking, credentials, GitHub/MCP OAuth custody, and MCP battery ====="
	GANTRY_ARTIFACTS="$MAC_ARTIFACTS" \
		GANTRY_TEST_PUBLIC_EGRESS="$MAC_PUBLIC_EGRESS" \
		GANTRY_TEST_ROOT="$ROOT" \
		GANTRY_TEST_OAUTH_IDP="$MAC_OAUTH_IDP" \
		GANTRY_TEST_EXE="$MAC_GANTRY" \
		GANTRY_TEST_KERNEL="$MAC_KERNEL" \
		GANTRY_TEST_ROOTFS="$MAC_ROOTFS" \
		GANTRY_TEST_IMAGE="$MAC_WORKLOAD" \
		GANTRY_TEST_EXPECTED_ARCH=aarch64 \
		GANTRY_HOME="$MAC_TMP/functional/sandboxes" \
		GANTRY_IMAGES="$MAC_TMP/functional/images" \
		GANTRY_STORE_URL='' \
		bash scripts/aws-kvm/test-battery.sh

	echo "===== macOS HVF: signed OPA organization-policy battery ====="
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build \
		-o "$MAC_TMP/policy-e2e" ./tests/e2e/policy
	"$MAC_TMP/policy-e2e" \
		-gantry "$MAC_GANTRY" -kernel "$MAC_KERNEL" -rootfs "$MAC_ROOTFS" \
		-image "$MAC_WORKLOAD" -artifacts "$MAC_ARTIFACTS"

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

run_linux_validation() {
	[ "$(uname -s)" = Linux ] || {
		echo "linux validation must run on Linux" >&2
		exit 1
	}
	case $(uname -m) in
	x86_64|amd64)
		LINUX_ASSET_ARCH=x86_64
		LINUX_GOARCH=amd64
		LINUX_EXPECTED_ARCH=x86_64
		;;
	aarch64|arm64)
		LINUX_ASSET_ARCH=arm64
		LINUX_GOARCH=arm64
		LINUX_EXPECTED_ARCH=aarch64
		;;
	*) echo "local Linux validation does not support $(uname -m)" >&2; exit 1 ;;
	esac
	[ -c /dev/kvm ] || { echo "local Linux validation requires /dev/kvm" >&2; exit 1; }
	for command_name in go python3 curl ssh sftp; do
		command -v "$command_name" >/dev/null 2>&1 || {
			echo "required command not found: $command_name" >&2
			exit 1
		}
	done

	linux_absolute() {
		case $1 in
		/*) printf '%s\n' "$1" ;;
		*) printf '%s/%s\n' "$ROOT" "$1" ;;
		esac
	}
	LINUX_ARTIFACTS=$(linux_absolute "${GANTRY_ARTIFACTS:-artifacts}")
	LINUX_GANTRY=$(linux_absolute "${GANTRY_TEST_EXE:-$LINUX_ARTIFACTS/gantry}")
	LINUX_GUEST=$LINUX_ARTIFACTS/gantry-guest-$LINUX_ASSET_ARCH
	LINUX_KERNEL=$(linux_absolute "${GANTRY_TEST_KERNEL:-$LINUX_ARTIFACTS/gantry-kernel-$LINUX_ASSET_ARCH}")
	LINUX_ROOTFS=$(linux_absolute "${GANTRY_TEST_ROOTFS:-$LINUX_ARTIFACTS/nerdbox-rootfs-$LINUX_ASSET_ARCH.erofs}")
	LINUX_IMAGE=$(linux_absolute "${GANTRY_TEST_WORKLOAD_IMAGE:-$LINUX_ARTIFACTS/gantry-default-image-$LINUX_ASSET_ARCH.erofs}")
	LINUX_RUNSC_KERNEL=
	LINUX_RUNSC_ROOTFS=
	[ -z "${GANTRY_TEST_RUNSC_KERNEL:-}" ] || LINUX_RUNSC_KERNEL=$(linux_absolute "$GANTRY_TEST_RUNSC_KERNEL")
	[ -z "${GANTRY_TEST_RUNSC_ROOTFS:-}" ] || LINUX_RUNSC_ROOTFS=$(linux_absolute "$GANTRY_TEST_RUNSC_ROOTFS")
	if { [ -n "$LINUX_RUNSC_KERNEL" ] && [ -z "$LINUX_RUNSC_ROOTFS" ]; } ||
		{ [ -z "$LINUX_RUNSC_KERNEL" ] && [ -n "$LINUX_RUNSC_ROOTFS" ]; }; then
		echo "GANTRY_TEST_RUNSC_KERNEL and GANTRY_TEST_RUNSC_ROOTFS must be set together" >&2
		exit 1
	fi
	for executable in "$LINUX_GANTRY" "$LINUX_GUEST"; do
		[ -x "$executable" ] || { echo "missing executable: $executable" >&2; exit 1; }
	done
	set -- "$LINUX_KERNEL" "$LINUX_ROOTFS" "$LINUX_IMAGE"
	[ -z "$LINUX_RUNSC_KERNEL" ] || set -- "$@" "$LINUX_RUNSC_KERNEL" "$LINUX_RUNSC_ROOTFS"
	for asset in "$@"; do
		[ -s "$asset" ] || { echo "missing guest asset: $asset" >&2; exit 1; }
	done

	LINUX_PUBLIC_EGRESS=${GANTRY_TEST_PUBLIC_EGRESS:-}
	if [ -z "$LINUX_PUBLIC_EGRESS" ]; then
		if python3 -c 'import socket; s = socket.create_connection(("1.1.1.1", 443), 5); s.close()' \
			>/dev/null 2>&1; then
			LINUX_PUBLIC_EGRESS=required
		else
			LINUX_PUBLIC_EGRESS=skip
			echo "Linux host has no direct public TCP path; public guest egress checks will be skipped" >&2
		fi
	fi

	LINUX_OWNED_WORK=0
	if [ -n "${GANTRY_E2E_WORK_DIR:-}" ]; then
		LINUX_WORK=$GANTRY_E2E_WORK_DIR
		mkdir -p "$LINUX_WORK"
	else
		LINUX_WORK=$(mktemp -d /tmp/gantry-le2e.XXXXXX)
		LINUX_OWNED_WORK=1
	fi
	LINUX_WORK=$(CDPATH='' cd -- "$LINUX_WORK" && pwd -P)
	# shellcheck disable=SC2317 # Called indirectly by the EXIT trap.
	cleanup_linux() {
		status=$?
		trap - EXIT HUP INT TERM
		if [ "$LINUX_OWNED_WORK" -eq 1 ] && [ "$status" -eq 0 ]; then
			rm -rf -- "$LINUX_WORK"
		else
			echo "Linux E2E workspace: $LINUX_WORK"
		fi
		exit "$status"
	}
	trap cleanup_linux EXIT
	trap 'exit 130' HUP INT TERM

	# Batteries also start sandboxes without -kernel/-rootfs. Those resolve
	# Gantry's defaults by canonical release basename below GANTRY_ARTIFACTS
	# and download any missing asset from the GitHub release, so caller
	# overrides with other names (as in CI) would silently exercise the
	# published release instead, and fail while a new release is still being
	# built. Stage the selected assets under their canonical names in the
	# private test tree and point every battery at it.
	LINUX_FIELD_ASSETS=$LINUX_WORK/field-assets
	mkdir -p "$LINUX_FIELD_ASSETS"
	stage_linux_asset() {
		source_path=$1
		destination_path=$2
		rm -f -- "$destination_path"
		ln "$source_path" "$destination_path" 2>/dev/null || cp "$source_path" "$destination_path"
	}
	stage_linux_asset "$LINUX_GUEST" "$LINUX_FIELD_ASSETS/gantry-guest-$LINUX_ASSET_ARCH"
	stage_linux_asset "$LINUX_KERNEL" "$LINUX_FIELD_ASSETS/gantry-kernel-$LINUX_ASSET_ARCH"
	stage_linux_asset "$LINUX_ROOTFS" "$LINUX_FIELD_ASSETS/nerdbox-rootfs-$LINUX_ASSET_ARCH.erofs"
	stage_linux_asset "$LINUX_IMAGE" "$LINUX_FIELD_ASSETS/gantry-default-image-$LINUX_ASSET_ARCH.erofs"
	if [ -n "$LINUX_RUNSC_KERNEL" ]; then
		# gVisor needs 4K pages: arm64 uses a separate -4k kernel, while
		# x86_64 boots the regular kernel staged above.
		[ "$LINUX_ASSET_ARCH" != arm64 ] ||
			stage_linux_asset "$LINUX_RUNSC_KERNEL" "$LINUX_FIELD_ASSETS/gantry-kernel-arm64-4k"
		stage_linux_asset "$LINUX_RUNSC_ROOTFS" "$LINUX_FIELD_ASSETS/nerdbox-rootfs-gvisor-$LINUX_ASSET_ARCH.erofs"
	fi

	LINUX_OAUTH_IDP=$(linux_absolute "${GANTRY_TEST_OAUTH_IDP:-$LINUX_WORK/gantry-oauth-idp}")
	if [ -z "${GANTRY_TEST_OAUTH_IDP:-}" ]; then
		echo "===== Linux KVM: build disposable OAuth authorization server ====="
		CGO_ENABLED=0 go build -o "$LINUX_OAUTH_IDP" ./tests/e2e/oauthidp
	fi
	[ -x "$LINUX_OAUTH_IDP" ] || { echo "missing OAuth fixture: $LINUX_OAUTH_IDP" >&2; exit 1; }

	echo "===== Linux KVM: manager API, remote dashboard parity, SSH, and organization policy-feed battery ====="
	rm -rf -- "$LINUX_WORK/manager"
	GANTRY_ARTIFACTS="$LINUX_FIELD_ASSETS" scripts/test-manager-api-e2e.sh \
		-gantry "$LINUX_GANTRY" -artifacts "$LINUX_FIELD_ASSETS" \
		-kernel "$LINUX_KERNEL" -rootfs "$LINUX_ROOTFS" -image "$LINUX_IMAGE" \
		-image-store "$LINUX_WORK/manager-images" -pull=false \
		-work-dir "$LINUX_WORK/manager" -timeout 12m

	echo "===== Linux KVM: core CLI, networking, credentials, OAuth custody, and MCP battery ====="
	GANTRY_ARTIFACTS="$LINUX_FIELD_ASSETS" \
		GANTRY_TEST_PUBLIC_EGRESS="$LINUX_PUBLIC_EGRESS" \
		GANTRY_TEST_ROOT="$ROOT" \
		GANTRY_TEST_OAUTH_E2E="$ROOT/scripts/oauth-custody-e2e.py" \
		GANTRY_TEST_OAUTH_IDP="$LINUX_OAUTH_IDP" \
		GANTRY_TEST_EXE="$LINUX_GANTRY" \
		GANTRY_TEST_KERNEL="$LINUX_KERNEL" \
		GANTRY_TEST_ROOTFS="$LINUX_ROOTFS" \
		GANTRY_TEST_IMAGE="$LINUX_IMAGE" \
		GANTRY_TEST_RUNSC_KERNEL="$LINUX_RUNSC_KERNEL" \
		GANTRY_TEST_RUNSC_ROOTFS="$LINUX_RUNSC_ROOTFS" \
		GANTRY_TEST_EXPECTED_ARCH="$LINUX_EXPECTED_ARCH" \
		GANTRY_HOME="$LINUX_WORK/functional/sandboxes" \
		GANTRY_IMAGES="$LINUX_WORK/functional/images" \
		GANTRY_STORE_URL='' \
		bash scripts/aws-kvm/test-battery.sh

	echo "===== Linux KVM: signed OPA organization-policy battery ====="
	CGO_ENABLED=0 go build -o "$LINUX_WORK/policy-e2e" ./tests/e2e/policy
	"$LINUX_WORK/policy-e2e" \
		-gantry "$LINUX_GANTRY" -kernel "$LINUX_KERNEL" -rootfs "$LINUX_ROOTFS" \
		-image "$LINUX_IMAGE" -artifacts "$LINUX_FIELD_ASSETS"

	if [ "${GANTRY_SKIP_DEVCONTAINERS:-0}" = 1 ]; then
		echo "===== Linux KVM: SSH/Dev Containers and directory batteries skipped ====="
	else
		LINUX_IDE_IMAGE=
		[ -z "${GANTRY_TEST_IDE_IMAGE:-}" ] || LINUX_IDE_IMAGE=$(linux_absolute "$GANTRY_TEST_IDE_IMAGE")
		if [ -z "$LINUX_IDE_IMAGE" ] && [ -s "$LINUX_ARTIFACTS/gantry-ide-image-$LINUX_ASSET_ARCH.erofs" ]; then
			LINUX_IDE_IMAGE=$LINUX_ARTIFACTS/gantry-ide-image-$LINUX_ASSET_ARCH.erofs
		fi
		if [ -z "$LINUX_IDE_IMAGE" ]; then
			for command_name in docker mkfs.erofs; do
				command -v "$command_name" >/dev/null 2>&1 || {
					echo "required to build the curated IDE image: $command_name" >&2
					echo "set GANTRY_TEST_IDE_IMAGE or GANTRY_SKIP_DEVCONTAINERS=1 to continue without building it" >&2
					exit 1
				}
			done
			LINUX_IDE_IMAGE=$LINUX_WORK/gantry-ide-image-$LINUX_ASSET_ARCH.erofs
			echo "===== Linux KVM: build current curated IDE image ====="
			sh scripts/mkideimage.sh "$LINUX_IDE_IMAGE" "linux/$LINUX_GOARCH"
		fi
		[ -s "$LINUX_IDE_IMAGE" ] || { echo "curated IDE image missing: $LINUX_IDE_IMAGE" >&2; exit 1; }

		stage_linux_asset "$LINUX_IDE_IMAGE" "$LINUX_FIELD_ASSETS/gantry-ide-image-$LINUX_ASSET_ARCH.erofs"
		LINUX_IDE_IMAGE=$LINUX_FIELD_ASSETS/gantry-ide-image-$LINUX_ASSET_ARCH.erofs

		echo "===== Linux KVM: SSH/Dev Containers battery ====="
		GANTRY_TEST_ROOT="$LINUX_FIELD_ASSETS" \
			GANTRY_TEST_EXE="$LINUX_GANTRY" \
			GANTRY_TEST_KERNEL="$LINUX_KERNEL" \
			GANTRY_TEST_ROOTFS="$LINUX_ROOTFS" \
			GANTRY_TEST_IDE_IMAGE="$LINUX_IDE_IMAGE" \
			GANTRY_TEST_WORKLOAD_IMAGE="$LINUX_IMAGE" \
			GANTRY_TEST_GUEST="$LINUX_FIELD_ASSETS/gantry-guest-$LINUX_ASSET_ARCH" \
			GANTRY_TEST_SANDBOX="ssh-devcontainers-$LINUX_ASSET_ARCH-kvm" \
			GANTRY_TEST_PLATFORM="Linux $LINUX_ASSET_ARCH KVM" \
			GANTRY_HOME="$LINUX_WORK/ssh/sandboxes" \
			bash scripts/aws-kvm/ssh-devcontainers-validation.sh

		echo "===== Linux KVM: large-directory battery ====="
		GANTRY_TEST_ARCH="$LINUX_ASSET_ARCH" \
			GANTRY_TEST_ROOT="$LINUX_FIELD_ASSETS" \
			GANTRY_TEST_EXE="$LINUX_GANTRY" \
			GANTRY_TEST_KERNEL="$LINUX_KERNEL" \
			GANTRY_TEST_ROOTFS="$LINUX_ROOTFS" \
			GANTRY_TEST_IMAGE="$LINUX_IDE_IMAGE" \
			GANTRY_TEST_GUEST_DIR=/home/gantry/gantry-dirscan \
			GANTRY_TEST_SANDBOX="dirscan-$LINUX_ASSET_ARCH-kvm" \
			GANTRY_HOME="$LINUX_WORK/directory/sandboxes" \
			sh scripts/aws-kvm/directory-validation.sh
	fi

	echo "===== Linux KVM E2E VALIDATION PASSED ====="
}

case "$MODE" in
aws) ;;
linux) run_linux_validation; exit 0 ;;
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
export AWS_DEFAULT_REGION="$REGION"
ACCOUNT=$(aws sts get-caller-identity --region "$REGION" --query Account --output text)
BUCKET=${GANTRY_TEST_BUCKET:-gantry-kvm-test-$ACCOUNT}

instance_by_name() {
	name=$1
	aws ec2 describe-instances --region "$REGION" \
		--filters "Name=tag:Name,Values=$name" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
		--query 'Reservations[].Instances[].InstanceId' --output text | awk '{print $1}'
}

LINUX_IID=${GANTRY_LINUX_IID:-$(instance_by_name gantry-kvm-test)}
ARM_IID=${GANTRY_ARM_IID:-$(instance_by_name gantry-kvm-test-arm64)}
WINDOWS_IID=${GANTRY_WINDOWS_IID:-$(instance_by_name gantry-whpx-test)}
[ -n "$LINUX_IID" ] || { echo "Linux amd64 KVM instance not found (set GANTRY_LINUX_IID)" >&2; exit 1; }
[ -n "$ARM_IID" ] || { echo "Linux arm64 KVM instance not found (set GANTRY_ARM_IID)" >&2; exit 1; }
[ -n "$WINDOWS_IID" ] || { echo "Windows WHPX instance not found (set GANTRY_WINDOWS_IID)" >&2; exit 1; }

DIRECTORY_RUN=
IDE_BUILD_DIR=
POLICY_BUILD_DIR=
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	[ -z "$DIRECTORY_RUN" ] || rm -f -- "$DIRECTORY_RUN"
	[ -z "$IDE_BUILD_DIR" ] || rm -rf -- "$IDE_BUILD_DIR"
	[ -z "$POLICY_BUILD_DIR" ] || rm -rf -- "$POLICY_BUILD_DIR"
	if [ "${GANTRY_KEEP_INSTANCES:-0}" != 1 ]; then
		echo "== stopping AWS validation instances =="
		aws ec2 stop-instances --region "$REGION" \
			--instance-ids "$LINUX_IID" "$ARM_IID" "$WINDOWS_IID" >/dev/null 2>&1 || true
	else
		echo "== GANTRY_KEEP_INSTANCES=1: leaving instances running =="
	fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

# Compile the black-box policy driver from this checkout before starting EC2.
# It signs short-lived fixtures on each host: no stale signatures, controller-
# specific mount paths, private-key uploads, or remote Go/OPA dependencies.
POLICY_BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/gantry-policy-e2e.XXXXXX")
echo "== build Linux and Windows field-test drivers =="
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
	-o "$POLICY_BUILD_DIR/policy-linux-amd64" ./tests/e2e/policy
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
	-o "$POLICY_BUILD_DIR/policy-linux-arm64" ./tests/e2e/policy
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build \
	-o "$POLICY_BUILD_DIR/policy-windows-amd64.exe" ./tests/e2e/policy
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
	-o "$POLICY_BUILD_DIR/manager-api-linux-amd64" ./tests/e2e/managerapi
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
	-o "$POLICY_BUILD_DIR/manager-api-linux-arm64" ./tests/e2e/managerapi
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build \
	-o "$POLICY_BUILD_DIR/manager-api-windows-amd64.exe" ./tests/e2e/managerapi

# Keep a host-provided Docker API out of the HTTP proxy. Sandboxed callers use
# this endpoint to reach the host engine, and proxying it turns `_ping` into an
# unrelated outbound HTTP request.
case ${DOCKER_HOST:-} in
	tcp://host.docker.internal:*)
		case ,${NO_PROXY:-}, in
			*,host.docker.internal,*) ;;
			*) NO_PROXY=${NO_PROXY:+$NO_PROXY,}host.docker.internal ;;
		esac
		no_proxy=$NO_PROXY
		export NO_PROXY no_proxy
		;;
esac

# Build curated images from the current Dockerfile so the field run validates
# these source changes rather than stale release or S3 objects. A caller may
# provide already-built images when replaying in an air-gapped environment.
IDE_IMAGE=${GANTRY_TEST_IDE_IMAGE:-}
ARM_IDE_IMAGE=${GANTRY_TEST_ARM_IDE_IMAGE:-}
if [ -z "$IDE_IMAGE" ] || [ -z "$ARM_IDE_IMAGE" ]; then
	IDE_BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/gantry-ide-images.XXXXXX")
fi
if [ -z "$IDE_IMAGE" ]; then
	IDE_IMAGE=$IDE_BUILD_DIR/gantry-ide-image-x86_64.erofs
	sh scripts/mkideimage.sh "$IDE_IMAGE" linux/amd64
fi
if [ -z "$ARM_IDE_IMAGE" ]; then
	ARM_IDE_IMAGE=$IDE_BUILD_DIR/gantry-ide-image-arm64.erofs
	sh scripts/mkideimage.sh "$ARM_IDE_IMAGE" linux/arm64
fi
[ -s "$IDE_IMAGE" ] || { echo "curated amd64 IDE image missing: $IDE_IMAGE" >&2; exit 1; }
[ -s "$ARM_IDE_IMAGE" ] || { echo "curated arm64 IDE image missing: $ARM_IDE_IMAGE" >&2; exit 1; }
echo "== staging current curated IDE images =="
aws s3 cp "$IDE_IMAGE" "s3://$BUCKET/gantry-ide-image-x86_64.erofs" \
	--region "$REGION" --only-show-errors
aws s3 cp "$ARM_IDE_IMAGE" "s3://$BUCKET/gantry-ide-image-arm64.erofs" \
	--region "$REGION" --only-show-errors
aws s3 cp "$POLICY_BUILD_DIR/policy-linux-amd64" "s3://$BUCKET/e2e/policy-linux-amd64" \
	--region "$REGION" --only-show-errors
aws s3 cp "$POLICY_BUILD_DIR/policy-linux-arm64" "s3://$BUCKET/e2e/policy-linux-arm64" \
	--region "$REGION" --only-show-errors
aws s3 cp "$POLICY_BUILD_DIR/policy-windows-amd64.exe" "s3://$BUCKET/e2e/policy-windows-amd64.exe" \
	--region "$REGION" --only-show-errors
aws s3 cp "$POLICY_BUILD_DIR/manager-api-linux-amd64" "s3://$BUCKET/e2e/manager-api-linux-amd64" \
	--region "$REGION" --only-show-errors
aws s3 cp "$POLICY_BUILD_DIR/manager-api-linux-arm64" "s3://$BUCKET/e2e/manager-api-linux-arm64" \
	--region "$REGION" --only-show-errors
aws s3 cp "$POLICY_BUILD_DIR/manager-api-windows-amd64.exe" "s3://$BUCKET/e2e/manager-api-windows-amd64.exe" \
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
start_instance "$ARM_IID"
start_instance "$WINDOWS_IID"
wait_ssm "$LINUX_IID"
wait_ssm "$ARM_IID"
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

echo "===== Linux amd64 KVM: main field battery (including GitHub/MCP OAuth custody) ====="
GANTRY_TEST_IID=$LINUX_IID BUCKET=$BUCKET REGION=$REGION \
	sh scripts/aws-kvm/run-tests.sh 1800

echo "===== Linux arm64 KVM: required-confinement/share/MCP battery ====="
GANTRY_TEST_IID=$ARM_IID BUCKET=$BUCKET REGION=$REGION \
	sh scripts/aws-kvm/run-tests-arm64.sh 1800

# The preceding replays staged the current Gantry binaries and guest assets.
# Always replace the driver too, rather than reusing a prior field battery.
echo "===== Linux amd64 KVM: signed OPA organization-policy battery ====="
GANTRY_TEST_IID=$LINUX_IID GANTRY_TEST_REGION=$REGION \
	python3 scripts/aws-kvm/ssm.py --s3-download "$BUCKET" e2e/policy-linux-amd64 /opt/gantry/policy-e2e 600
GANTRY_TEST_IID=$LINUX_IID GANTRY_TEST_REGION=$REGION \
	python3 scripts/aws-kvm/ssm.py -c '
chmod +x /opt/gantry/policy-e2e
/opt/gantry/policy-e2e -gantry /opt/gantry/gantry-linux-amd64 \
  -kernel /opt/gantry/nerdbox-kernel-x86_64 \
  -rootfs /opt/gantry/nerdbox-rootfs-x86_64.erofs \
  -image /opt/gantry/gantry-ide-image-x86_64.erofs -artifacts /opt/gantry
' 1200

echo "===== Linux arm64 KVM: signed OPA organization-policy battery ====="
GANTRY_TEST_IID=$ARM_IID GANTRY_TEST_REGION=$REGION \
	python3 scripts/aws-kvm/ssm.py --s3-download "$BUCKET" e2e/policy-linux-arm64 /opt/gantry/policy-e2e 600
GANTRY_TEST_IID=$ARM_IID GANTRY_TEST_REGION=$REGION \
	python3 scripts/aws-kvm/ssm.py -c '
chmod +x /opt/gantry/policy-e2e
/opt/gantry/policy-e2e -gantry /opt/gantry/gantry-linux-arm64-current \
  -kernel /opt/gantry/gantry-kernel-arm64 \
  -rootfs /opt/gantry/nerdbox-rootfs-arm64.erofs \
  -image /opt/gantry/gantry-ide-image-arm64.erofs -artifacts /opt/gantry
' 1200

echo "===== Windows WHPX: signed OPA organization-policy battery ====="
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$WINDOWS_IID" \
	--s3-download "$BUCKET" e2e/policy-windows-amd64.exe C:/gantry/policy-e2e.exe 600
# Quote host paths as PowerShell literals, including paths containing apostrophes.
WINDOWS_POLICY_COMMAND=$(python3 - \
	"${GANTRY_TEST_EXE:-C:/gantry/gantry-field.exe}" \
	"${GANTRY_TEST_CURRENT_KERNEL:-C:/gantry/gantry-kernel-x86_64}" \
	"${GANTRY_TEST_CURRENT_ROOTFS:-C:/gantry/nerdbox-rootfs-x86_64.erofs}" \
	"${GANTRY_TEST_POLICY_IMAGE:-C:/gantry/gantry-ide-image-x86_64.erofs}" \
	"${GANTRY_TEST_ROOT:-C:/gantry}" <<'PY'
import sys

values = sys.argv[1:]
args = ["C:/gantry/policy-e2e.exe"]
for flag, value in zip(("-gantry", "-kernel", "-rootfs", "-image", "-artifacts"), values):
    args.extend((flag, value))
command = " ".join("'" + value.replace("'", "''") + "'" for value in args)
print("$ErrorActionPreference='Stop'; & " + command + "; exit $LASTEXITCODE")
PY
)
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$WINDOWS_IID" \
	-c "$WINDOWS_POLICY_COMMAND" 1200

echo "===== Linux amd64 KVM: live manager API, remote dashboard parity, and policy-feed battery ====="
GANTRY_TEST_IID=$LINUX_IID GANTRY_TEST_REGION=$REGION \
	python3 scripts/aws-kvm/ssm.py --s3-download "$BUCKET" e2e/manager-api-linux-amd64 /opt/gantry/manager-api-e2e 600
GANTRY_TEST_IID=$LINUX_IID GANTRY_TEST_REGION=$REGION \
	python3 scripts/aws-kvm/ssm.py -c '
chmod +x /opt/gantry/manager-api-e2e
rm -rf /opt/gantry/manager-e2e-run
/opt/gantry/manager-api-e2e -gantry /opt/gantry/gantry-linux-amd64 \
  -kernel /opt/gantry/nerdbox-kernel-x86_64 \
  -rootfs /opt/gantry/nerdbox-rootfs-x86_64.erofs \
  -image /opt/gantry/gantry-ide-image-x86_64.erofs -artifacts /opt/gantry \
  -pull=false -work-dir /opt/gantry/manager-e2e-run -timeout 15m
' 1800

echo "===== Linux arm64 KVM: live manager API, remote dashboard parity, and policy-feed battery ====="
GANTRY_TEST_IID=$ARM_IID GANTRY_TEST_REGION=$REGION \
	python3 scripts/aws-kvm/ssm.py --s3-download "$BUCKET" e2e/manager-api-linux-arm64 /opt/gantry/manager-api-e2e 600
GANTRY_TEST_IID=$ARM_IID GANTRY_TEST_REGION=$REGION \
	python3 scripts/aws-kvm/ssm.py -c '
chmod +x /opt/gantry/manager-api-e2e
rm -rf /opt/gantry/manager-e2e-run
/opt/gantry/manager-api-e2e -gantry /opt/gantry/gantry-linux-arm64-current \
  -kernel /opt/gantry/gantry-kernel-arm64 \
  -rootfs /opt/gantry/nerdbox-rootfs-arm64.erofs \
  -image /opt/gantry/gantry-ide-image-arm64.erofs -artifacts /opt/gantry \
  -pull=false -work-dir /opt/gantry/manager-e2e-run -timeout 15m
' 1800

echo "===== Windows WHPX: live manager API, remote dashboard parity, and policy-feed battery ====="
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$WINDOWS_IID" \
	--s3-download "$BUCKET" e2e/manager-api-windows-amd64.exe C:/gantry/manager-api-e2e.exe 600
WINDOWS_MANAGER_COMMAND=$(python3 - \
	"${GANTRY_TEST_EXE:-C:/gantry/gantry-field.exe}" \
	"${GANTRY_TEST_CURRENT_KERNEL:-C:/gantry/gantry-kernel-x86_64}" \
	"${GANTRY_TEST_CURRENT_ROOTFS:-C:/gantry/nerdbox-rootfs-x86_64.erofs}" \
	"${GANTRY_TEST_MANAGER_IMAGE:-C:/gantry/gantry-ide-image-x86_64.erofs}" \
	"${GANTRY_TEST_ROOT:-C:/gantry}" <<'PY'
import sys

values = sys.argv[1:]
args = ["C:/gantry/manager-api-e2e.exe"]
for flag, value in zip(("-gantry", "-kernel", "-rootfs", "-image", "-artifacts"), values):
    args.extend((flag, value))
args.extend(("-pull=false", "-work-dir", "C:/gantry/manager-e2e-run", "-timeout", "15m"))
command = " ".join("'" + value.replace("'", "''") + "'" for value in args)
print("$ErrorActionPreference='Stop'; Remove-Item -Recurse -Force C:/gantry/manager-e2e-run -ErrorAction SilentlyContinue; & " + command + "; exit $LASTEXITCODE")
PY
)
GANTRY_TEST_REGION=$REGION python3 scripts/aws-whpx/ssm.py "$WINDOWS_IID" \
	-c "$WINDOWS_MANAGER_COMMAND" 1800

echo "===== Linux amd64 KVM: SSH/Dev Containers battery ====="
GANTRY_TEST_IID=$LINUX_IID GANTRY_TEST_REGION=$REGION \
	python3 scripts/aws-kvm/ssm.py scripts/aws-kvm/ssh-devcontainers-validation.sh 1800

echo "===== Linux arm64 KVM: SSH/Dev Containers battery ====="
DIRECTORY_RUN=$(mktemp "${TMPDIR:-/tmp}/gantry-arm64-ssh.XXXXXX.sh")
{
	cat <<'EOF'
export GANTRY_TEST_ROOT=/opt/gantry
export GANTRY_TEST_EXE=/opt/gantry/gantry-linux-arm64-current
export GANTRY_TEST_KERNEL=/opt/gantry/gantry-kernel-arm64
export GANTRY_TEST_ROOTFS=/opt/gantry/nerdbox-rootfs-arm64.erofs
export GANTRY_TEST_IDE_IMAGE=/opt/gantry/gantry-ide-image-arm64.erofs
export GANTRY_TEST_WORKLOAD_IMAGE=/opt/gantry/ubuntu-arm64.erofs
export GANTRY_TEST_GUEST=/opt/gantry/gantry-guest-arm64
export GANTRY_TEST_SANDBOX=ssh-devcontainers-arm64-kvm
export GANTRY_TEST_PLATFORM='Linux arm64 KVM'
export GANTRY_HOME=/opt/gantry/state-ssh-devcontainers-arm64
EOF
	cat scripts/aws-kvm/ssh-devcontainers-validation.sh
} >"$DIRECTORY_RUN"
GANTRY_TEST_IID=$ARM_IID GANTRY_TEST_REGION=$REGION \
	python3 scripts/aws-kvm/ssm.py "$DIRECTORY_RUN" 1800
rm -f -- "$DIRECTORY_RUN"
DIRECTORY_RUN=

echo "===== Linux amd64 KVM: large-directory battery ====="
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

echo "===== Linux arm64 KVM: large-directory battery ====="
DIRECTORY_RUN=$(mktemp "${TMPDIR:-/tmp}/gantry-arm64-directory.XXXXXX.sh")
{
	cat <<'EOF'
export GANTRY_TEST_ARCH=arm64
export GANTRY_TEST_ROOT=/opt/gantry
export GANTRY_TEST_EXE=/opt/gantry/gantry-linux-arm64-current
export GANTRY_TEST_KERNEL=/opt/gantry/gantry-kernel-arm64
export GANTRY_TEST_ROOTFS=/opt/gantry/nerdbox-rootfs-arm64.erofs
export GANTRY_TEST_IMAGE=/opt/gantry/gantry-ide-image-arm64.erofs
export GANTRY_TEST_GUEST_DIR=/home/gantry/gantry-dirscan
export GANTRY_TEST_SANDBOX=dirscan-arm64-current
export GANTRY_HOME=/opt/gantry/state-directory-arm64
EOF
	cat scripts/aws-kvm/directory-validation.sh
} >"$DIRECTORY_RUN"
GANTRY_TEST_IID=$ARM_IID GANTRY_TEST_REGION=$REGION \
	python3 scripts/aws-kvm/ssm.py "$DIRECTORY_RUN" 2400
rm -f -- "$DIRECTORY_RUN"
DIRECTORY_RUN=

echo "===== Linux amd64 KVM: required-confinement battery ====="
GANTRY_TEST_IID=$LINUX_IID GANTRY_TEST_REGION=$REGION \
	python3 scripts/aws-kvm/ssm.py scripts/aws-kvm/confinement-battery.sh 1200

echo "===== AWS E2E VALIDATION PASSED ====="
