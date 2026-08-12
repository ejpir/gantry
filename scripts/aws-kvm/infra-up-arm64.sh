#!/bin/sh
# Create/reuse the dedicated AL2023 Graviton bare-metal KVM host.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

NAME=${NAME:-gantry-kvm-test-arm64}
INSTANCE_TYPE=${INSTANCE_TYPE:-c7g.metal}
AMI_PARAM=${AMI_PARAM:-/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64}
export NAME INSTANCE_TYPE AMI_PARAM

exec "$HERE/infra-up.sh" "$@"
