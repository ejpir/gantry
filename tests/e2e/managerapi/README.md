# Manager API end-to-end test

This black-box test launches `gantry serve` on an isolated Unix socket and
uses the local hypervisor to create, exec, stop, restart, and delete a real
sandbox. The shell entry point first runs the M2 safety tests, SSH gateway
unit tests and an OpenSSH protocol harness, then executes the black-box
battery. It also checks the OpenAPI endpoint, strict JSON validation,
idempotency, operation lookup, SSE lifecycle events, output/timeout bounds,
and secret-value non-persistence.

By default the manager is additionally launched with a self-signed TLS
listener, and the test exercises the remote transport before any VM work:
chain verification plus leaf-fingerprint pinning against the manager's
printed fingerprint, the bearer-authentication matrix (missing/wrong tokens
are indistinguishable 403s on every path), plaintext-HTTP refusal, live
token-file rotation, and — once a sandbox is running — the mutation audit
trail (remote address and token fingerprint logged, never the token value).
The full lifecycle and SSE checks then use authenticated TLS. It also starts a
separate local mTLS policy service, creates two running sandboxes, publishes a
newly signed organization generation, waits for the aggregate acknowledgement,
and verifies both sandboxes change without replacing either process. It also
checks that the active feed policy cannot be cleared per sandbox or bypassed
with a low-level raw VM. Before policy publication, an additional real CLI
battery uses a **separate client state tree/cwd**, covering
`start → exec → configure → stop → configure → resume → exec → delete` and a
bounded low-level `run` against the same verified boot assets. Live resource
changes must report restart-required without changing active allocation;
stopped changes must be active after resume. Raw VM deadline exit must be 124.
The M2 CLI fixture starts with a **writable overlay and SSH disabled**, then
explicitly enables SSH live. The overlay permits verified guest-tool delivery
through the share hub; a read-only root would force the bulk exec-channel
fallback. The earlier API lifecycle still covers `rw=false`. SSH verification
remains mandatory: delivery or integrity failures fail the test, not skip it.

### Real SSH and SFTP coverage (default full battery)

Stock **`ssh` and `sftp` must be in PATH**; missing tools fail preflight rather
than silently skipping SSH. Connections use Gantry's real `ssh-proxy` and
`ssh-known-hosts` helpers over the authenticated TLS manager upgrade, not a
direct connection to the local sandbox socket. The battery checks:

- SSH command output, argument quoting and nonzero guest exit status.
- SFTP binary upload/download (32 KiB, byte-for-byte comparison), paths with
  spaces, and removal of the guest files/directories.
- Rejection of non-loopback `direct-tcpip` forwarding by the gateway policy.
- Live SSH disable: HTTP upgrade refusal (409) and OpenSSH connection failure.
- Real rotation of the **disposable manager's** install key while SSH is off;
  KnownHostsCommand/OpenSSH refusal without overwriting the old pin, explicit
  `--accept-new-key`, and successful command execution with the new key.
- SSH remains disabled after a stopped configuration update and resume.
- Authenticated upgrade/refusal audit records, without bearer-token leakage.

The test uses private OpenSSH configuration/trust files, batch mode and bounded
command deadlines. It neither modifies nor reads the user's SSH config or
uses their authentication agent/keys. It does not yet cover interactive PTY
resize, rsync, VS Code, or the `gantry ssh setup` installer.

Manager-only M2 checks run before VM creation: wrong-pin refusal; PATCH
configuration false/omission preservation; idempotent replay and mismatch;
operation lookup; new-route pre-body authentication; raw helper failure/exit
and replay; unknown-profile refusal; explicit local override; and assertions
that same-named local sandbox fixtures were not modified. Mutation audit checks
cover both PATCH configuration and POST raw run.

Disable network-specific coverage explicitly with `-tls=false`; the default
includes it. This disables the extra remote CLI battery, not merely TLS health.

Run it from the repository root:

```sh
./scripts/test-manager-api-e2e.sh
```

### Without a hypervisor or guest assets

```sh
./scripts/test-manager-api-e2e.sh -api-only
```

This still builds/starts the **real manager**, uses real verified TLS and the
real client/helper binaries, and exercises all manager-only checks above. It
uses stopped configuration fixtures and a deliberate missing-asset raw-run
failure, not a fake successful VM. It neither downloads assets nor boots guests.
`-api-only -tls=false` is rejected rather than silently skipping remote tests.
A passing API-only run does **not** sign off VM boot, organization-wide live
policy-feed updates, live configuration or resource application after restart,
or guest SSH/SFTP; run the default battery
on a suitable host. The script's protocol regression (`TestOpenSSHManagerTunnelHarness`)
uses real OpenSSH, compiled Gantry helpers and the production manager/gateway
with a fixture executor and in-memory SFTP filesystem. It validates the test
plumbing without claiming VM coverage; unlike the full runner, that unit test
may skip when OpenSSH is unavailable or Go's `-short` flag is used.

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
preserved and printed. Failed sandboxes are **stopped, not deleted**, retaining
`sandboxes/NAME/daemon.log` (including guest-tools failure details), prior-boot
logs and configuration. The current daemon log tail is printed before the
manager log tail. `-keep` preserves the workspace after success too.

Automatic workspaces are created below short `/tmp/gme-*` paths on Unix so
the nested manager, control, and vsock endpoints fit Darwin's 104-byte Unix
socket path limit. A custom `-work-dir` is rejected early when it would exceed
the platform's socket budget.
