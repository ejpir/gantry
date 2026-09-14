# Remote onboarding TUI E2E

Drive the **real Gantry binary** through a POSIX pseudo-terminal. No external
account, catalog deployment, registry, Docker, VM, or hypervisor is needed.
Requires Go and Python 3; the PTY driver uses only Python's standard library.
Run from the repository root on Linux or macOS:

```sh
go build -o /tmp/gantry-remotetui ./cmd/gantry
go run ./tests/e2e/remotetui -gantry /tmp/gantry-remotetui
```

Use a development build so automatic release checks remain disabled. Optional
`-python` and `-script` flags select the Python executable and driver path.
All fixture keys/tokens/state are disposable and removed after the run. The
fixture directory is private and secret metadata is never passed in argv.

## Coverage

- Open Create Sandbox and choose **Local / Remote / Organization** through the
  real rendered dialog and keyboard event loop.
- **Standalone**: add a remote without any organization configuration/receipt;
  reject bad authentication without saving; retry with the masked manager token;
  verify token-free profile JSON and a `0600` token file. The real CLI additionally
  refuses that token after temporarily making it group-readable.
- Return from registration to the explicitly remote create form. A cold remote
  image cache triggers an authenticated, idempotent pull and operation polling,
  followed by creation on the chosen manager. No local sandbox state is created,
  despite an unrelated `GANTRY_REMOTE` default.
- Use the **Remotes** page to test and remove a profile and token, with no remote
  sandbox deletion/mutation. Dynamic inventory appears without reopening the TUI.
- **Organization**: enter trusted configuration in the TUI, complete real OIDC
  discovery / authorization-code / PKCE / ID-token verification against our local
  HTTPS test IdP, and fetch an audience/scope-checked dynamic catalog.
- Discovery does not register profiles or reuse OIDC credentials. Enter a
  **separate manager token**, then create with the selected signed policy. The
  manager fixture verifies that snapshot. Receipt files are scanned for ID,
  access, refresh, authorization-code and verifier leakage.
- The terminal transcript is checked for plaintext manager-token leakage, and
  both TUI processes must exit cleanly.

The browser launcher alone is replaced through the subprocess `PATH`; the Go
fixture performs synthetic browser navigation to the real IdP/callback. There
are no production authentication bypass flags or alternate login verifiers.
The screen reader interprets cursor addressing so waits do not accidentally
match text left over from an earlier dialog.

## Deliberate limits

The manager is an HTTPS **protocol fixture**, not a VM backend. This battery
validates real-binary TUI/client/authentication/routing behavior; it does not
boot a guest, exercise SSH/SFTP, check real registry helpers or enforce guest
egress. Use `tests/e2e/managerapi` and the VM/policy batteries on a KVM/HVF/WHPX
host for those checks. This is not certification against a production IdP or
catalog service.

The PTY driver is POSIX-only; CI runs it on Linux and macOS. Windows keeps the
cross-platform Go unit/contract tests and standalone OIDC CLI E2E. No Windows
TUI/ConPTY coverage is claimed.
