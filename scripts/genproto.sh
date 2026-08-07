#!/bin/sh
# Regenerate the checked-in protobuf bindings under api/services/ from the
# vendored proto sources under api/proto/.
#
#   scripts/genproto.sh           regenerate in place
#   scripts/genproto.sh --check   regenerate into a scratch dir and verify
#                                 the checked-in files are byte-identical
#
# Toolchain pins reproduce the exact upstream (containerd/nerdbox@v0.2.1)
# generated files:
#
#   protoc-gen-go       v1.28.1   (stamped in info.pb.go)
#   protoc-gen-go-ttrpc ttrpc v1.2.9 (our go.mod's ttrpc version;
#                                     prefix=TTRPC per api/buf.gen.yaml)
#   buf                 v1.32.2   (compiler frontend; its version is not
#                                  stamped into generated output)
set -eu

BUF_VERSION=v1.32.2
PROTOC_GEN_GO_VERSION=v1.28.1
TTRPC_VERSION=v1.2.9

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

# Private scratch area for the tool binaries (and, in --check mode, the
# regeneration output). Never a predictable path, always cleaned up.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/gantry-genproto.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

export GOBIN="$WORK/bin"
mkdir -p "$GOBIN"
echo "installing pinned generators into scratch GOBIN..." >&2
go install "google.golang.org/protobuf/cmd/protoc-gen-go@$PROTOC_GEN_GO_VERSION"
go install "github.com/containerd/ttrpc/cmd/protoc-gen-go-ttrpc@$TTRPC_VERSION"
go install "github.com/bufbuild/buf/cmd/buf@$BUF_VERSION"
export PATH="$GOBIN:$PATH"

if [ "${1:-}" = "--check" ]; then
	# Copy ONLY the sources (proto + buf configs) so the check proves the
	# generated tree can be rebuilt from them alone.
	mkdir -p "$WORK/src"
	cp -a "$REPO/api/proto" "$REPO/api/buf.yaml" "$REPO/api/buf.gen.yaml" "$WORK/src/"
	(cd "$WORK/src" && buf generate)
	# Compare exactly the files buf produced (the checked-in tree may
	# additionally carry hand-written files like doc.go).
	drift=0
	for f in $(cd "$WORK/src" && find services -type f -print); do
		if ! diff -q "$WORK/src/$f" "$REPO/api/$f" >/dev/null 2>&1; then
			echo "drift: api/$f" >&2
			drift=1
		fi
	done
	if [ "$drift" -ne 0 ]; then
		echo "genproto --check FAILED: checked-in api/services/ does not match" >&2
		echo "the vendored sources; run scripts/genproto.sh to regenerate." >&2
		exit 1
	fi
	echo "genproto --check OK: api/services/ matches the vendored proto sources."
else
	(cd "$REPO/api" && buf generate)
	echo "regenerated api/services/ from api/proto/."
fi
