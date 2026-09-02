# api/ — guest agent RPC bindings

`services/system/v1/` contains the generated Go + ttrpc bindings for the
guest's system-Info service (`gantry exec`/session bootstrap asks vminitd
for its version). The files are **generated and checked in** — do not edit
them by hand.

## Provenance

The service definition is based on
[containerd/nerdbox](https://github.com/containerd/nerdbox) v0.2.4
(`api/proto/nerdbox/services/system/v1/info.proto`, Apache-2.0, copyright
The containerd Authors), plus Gantry's trusted `Sync` RPC extension. Its
upstream `go_package` option is retained so the standard services remain wire
compatible while Gantry and its patched `vminitd` share the generated binding.

## Regenerating

```sh
scripts/genproto.sh           # regenerate in place
scripts/genproto.sh --check   # verify checked-in files match the sources
```

The script installs the pinned generators (protoc-gen-go v1.28.1,
protoc-gen-go-ttrpc from containerd/ttrpc v1.2.9, buf v1.32.2) into a
scratch directory and runs buf against `api/proto/` using `api/buf.yaml`
and `api/buf.gen.yaml` (a local-plugin mirror of upstream's generation
template). `--check` regenerates into a scratch tree and diffs it against
the checked-in files, so CI can fail if they ever drift apart.
