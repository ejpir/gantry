# Manager API end-to-end test

This black-box test launches `gantry serve` on an isolated Unix socket and
uses the local hypervisor to create, exec, stop, restart, and delete a real
sandbox. It also checks the OpenAPI endpoint, strict JSON validation,
idempotency, operation lookup, SSE lifecycle events, output/timeout bounds,
and secret-value non-persistence.

Run it from the repository root:

```sh
./scripts/test-manager-api-e2e.sh
```

The runner builds a temporary Gantry binary (including the macOS hypervisor
entitlement). By default it downloads Gantry's checksummed built-in image from
the latest release and reuses it from the user cache; it does not contact an
OCI registry. Existing assets and images can be selected explicitly:

```sh
./scripts/test-manager-api-e2e.sh \
  -gantry ./artifacts/gantry \
  -artifacts ./artifacts \
  -image builtin
```

Use `-image builtin` for the default, `-pull=false` for an already cached
OCI reference (optionally with `-image-store`), or `-image /path/root.erofs`
for a local image. Registry access occurs only when an explicit OCI reference
is selected. On failure, the isolated workspace and `manager.log` are
preserved and printed; `-keep` preserves them after success too.

Automatic workspaces are created below short `/tmp/gme-*` paths on Unix so
the nested manager, control, and vsock endpoints fit Darwin's 104-byte Unix
socket path limit. A custom `-work-dir` is rejected early when it would exceed
the platform's socket budget.
