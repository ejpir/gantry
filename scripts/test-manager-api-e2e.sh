#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
# Keep the milestone-2 safety checks coupled to the black-box battery. They
# cover wire/flag parity, explicit false values, replay, launch locks, bounded
# helper output, cancellation, no-local-fallback and the OpenSSH tunnel
# protocol harness without needing a VM.
case "${1-}" in
  -h|--help) exec go run ./tests/e2e/managerapi "$@" ;;
esac

go test -count=1 ./cmd/gantry ./internal/runvm ./internal/remote \
  ./internal/sandbox/manager ./internal/sandbox/controlcmd \
  ./internal/sandbox/sshgw ./tests/e2e/managerapi
go test -count=1 ./internal/sandbox -run '^(TestManagerRun|TestConfigure)'

# Default: TLS lifecycle + real VM/raw-run + SSH exec/SFTP, channel-policy,
# live-disable and host-key rotation checks (requires OpenSSH ssh and sftp).
# -api-only explicitly selects the no-assets/no-hypervisor manager subset;
# it does not claim guest SSH/SFTP validation.
exec go run ./tests/e2e/managerapi "$@"
