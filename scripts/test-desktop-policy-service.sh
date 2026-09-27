#!/bin/sh
# Run the desktop's organization client against a real gantry policy-service:
# registration through the CLI profile store, workspace detection, and every
# administrator write, including signing with the CLI (desktop/tests/org_service.rs).
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
work=$(mktemp -d "${TMPDIR:-/tmp}/gantry-desktop-org.XXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM

go build -o "$work/gantry" ./cmd/gantry
cd desktop
GANTRY_TEST_GANTRY="$work/gantry" cargo test --locked --no-default-features --test org_service -- --nocapture
