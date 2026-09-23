#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
# Keep the milestone-2 safety checks coupled to the black-box battery. They
# cover wire/flag parity, explicit false values, replay, launch locks, bounded
# helper output, cancellation, no-local-fallback, source-scoped remote dashboard
# routing and the OpenSSH tunnel protocol harness without needing a VM.
case "${1-}" in
  -h|--help) exec go run ./tests/e2e/managerapi "$@" ;;
esac

go test -count=1 ./cmd/gantry ./internal/runvm ./internal/remote ./internal/dashboard \
  ./internal/policy ./internal/policyfeed ./internal/policyservice \
  ./internal/sandbox/manager ./internal/sandbox/controlcmd \
  ./internal/sandbox/sshgw ./tests/e2e/managerapi
go test -count=1 ./internal/sandbox -run '^(TestManagerRun|TestConfigure)'

# Both modes start the real `gantry policy-service`, enroll the manager with
# `gantry policy feed-request`, and sign every generation with `gantry policy
# sign`: publish, update, and roll back must each be acknowledged by the host
# over the mTLS long-poll feed with a matching digest.
# Default: TLS lifecycle + remote dashboard telemetry/actions/packet capture +
# real VM/raw-run + SSH exec/SFTP, live policy-service rollouts to two running
# sandboxes, SSH channel-policy, live-disable and host-key rotation
# checks (requires OpenSSH ssh and sftp).
# -api-only explicitly selects the no-assets/no-hypervisor manager subset
# (policy-service rollouts reach an empty host); it does not claim guest
# SSH/SFTP validation.
exec go run ./tests/e2e/managerapi "$@"
