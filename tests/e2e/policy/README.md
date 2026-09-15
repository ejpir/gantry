# Organization-policy field battery

This is a black-box test driver for the **real Gantry CLI, daemon, guest,
native network enforcement and MCP worker**. `scripts/aws-e2e-validation.sh` builds and
runs it on Linux KVM, Windows WHPX and local macOS HVF. It runs even when the
macOS Dev Containers batteries are skipped. It uses the normal `auto`
topology; on Windows, explicit loopback access uses Gantry's supported
monolithic-network fallback rather than requesting an unsupported AppContainer
loopback exemption.

Only the HTTP/MCP upstreams are fixtures. They listen on host loopback; guest
traffic reaches them through the normal virtual host alias. No public network
access, company account, external policy server, OPA CLI, OpenSSL executable,
or signing-key upload is needed. The driver creates a fresh RSA key in memory
and standard signed OPA bundles on each target host, with that host's real
mount paths and clock.

## Coverage

- Valid signatures, provenance, offline allow/deny checks, and distinct
  tampered/unsigned/wrong-key/unknown-profile/expired rejection cases.
- Invalid policy fails startup before sandbox state or writable disks exist.
- Governed OAuth custody is explicitly rejected (a current v1 limitation).
- Governed helper bootstrap uses the daemon-owned payload share without a
  grant for host staging directories; ordinary use of its tag cannot bypass policy.
- Initial and live mount admission, actual read-only enforcement in the guest,
  denied writable replacement, and preservation of the old export.
- Real guest TCP and DNS allow/deny, including deny-overrides, healthy positive
  controls, and host connection counters proving denied sockets never arrive.
- Local `net-policy default` and broad allow rules cannot remove org restrictions.
- Host-bound credential allow/deny with both hosts allowed by the DNS guard,
  so the negative case really exercises the credential policy.
- MCP listing filters a locally unrestricted remote; direct invocation works
  without a listing, while both listed-only and hidden tools are denied at
  invocation. Upstream counters prove denied calls are never forwarded.
- A permitted MCP tool cannot bypass an organization network denial through
  the supervisor's host-side dial broker.
- Live org-policy set/clear refusal; signed snapshot/key pinning across restart
  after changing the source files; stopped replacement applies the new revision;
  stopped clear restores local-only behavior.
- Live and stopped-command audit provenance, absence of credential/argument
  canaries in audit (including the persisted log) and config,
  runtime expiry shutdown with an attributed reason, and expired-resume refusal.

Negative checks assert **both the expected exit status and a specific reason**.
Missing guest tools, command timeouts, oversized output, missing responses,
and missing audit artifacts are failures, not successful denials.

## Run directly

Build for the host running the driver (Gantry itself must already be built;
its macOS binary must have the normal hypervisor entitlement):

```sh
go build -o /tmp/gantry-policy-e2e ./tests/e2e/policy
/tmp/gantry-policy-e2e \
  -gantry /path/to/gantry \
  -kernel /path/to/kernel \
  -rootfs /path/to/nerdbox-rootfs.erofs \
  -image /path/to/workload.erofs \
  -artifacts /path/to/current/guest-helper-directory
```

The workload needs `sh`, `cat`, `timeout`, curl or wget, and nslookup or glibc
getent. Alpine and the maintained Debian field images are supported. All
assets are local; no registry pull is performed. The current guest helper is
staged by Gantry through its ordinary helper-delivery path.

A normal run ends with `Policy E2E: N checks passed` and exits nonzero on any
failed check. The default overall deadline is 12 minutes. The expiry scenario
uses a 90-second signed lifetime; override `-expiry-window` (minimum 30 seconds)
for unusually slow test hosts.

Each run owns a fresh, private `GANTRY_HOME`, image store, fixtures and names.
Cleanup stops/deletes only its own sandboxes, including after failure or signal.
`commands.log` is bounded per command and redacts credential canaries. Failures
preserve the workspace for diagnosis; `-keep` also preserves successful runs.
Use `-work-dir` to select an existing parent directory; keep it short on Unix
because virtual-machine Unix socket paths have tight length limits.

## Validate without a hypervisor

```sh
go test ./tests/e2e/policy
go test -race ./tests/e2e/policy
/tmp/gantry-policy-e2e -gantry /path/to/gantry -cli-only
sh -n scripts/aws-e2e-validation.sh
python3 -m unittest scripts/test_aws_e2e_validation.py
```

`-cli-only` runs real signing/verification and offline decision checks. It
prints **`Policy CLI`**, never `Policy E2E`, and is not used by the orchestrator.
It does not substitute for the real-VM battery. The Python tests exercise
orchestrator staging, quoting, error propagation and cleanup using fake tools
in a private checkout; they never call AWS or start machines.
