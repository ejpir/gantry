#!/bin/sh
# Stop/terminate the dedicated Graviton host using infra-down's normal policy.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

NAME=${NAME:-gantry-kvm-test-arm64}
export NAME

exec "$HERE/infra-down.sh" "$@"
