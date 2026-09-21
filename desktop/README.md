# Gantry Desktop — native preview

A native Rust / [GPUI Kit](https://github.com/longbridge/gpui-kit) frontend for
Gantry. The inspector is **read-only** and uses the same HTTP/JSON manager API
over a local Unix socket or remote HTTPS. Local mode starts its manager on
demand; closing the window does not stop the manager or any sandbox.

![Gantry Desktop in dark mode, showing explicitly labeled demo data](assets/preview-dark.png)

## Run locally — no separate serve command

Install a current stable Rust toolchain and an up-to-date Gantry CLI supporting
`gantry serve --ensure`. Commands below run from the repository root.

```sh
cargo run --locked --manifest-path desktop/Cargo.toml
```

The desktop first tries `~/.gantry/manager.sock`. If it is absent, it invokes
Gantry's bounded, single-instance startup command, then connects to the same
socket. It does not read sandbox state files or speak the per-sandbox `ctl.sock`
protocol. All inventory and inspection still go through `/v1`.

For a source checkout, build the Go binary and select it explicitly:

```sh
go build -o artifacts/gantry ./cmd/gantry
cargo run --locked --manifest-path desktop/Cargo.toml -- --gantry ./artifacts/gantry
```

Without `--gantry`, the launcher looks beside the desktop executable, then on
`PATH`. It never invokes a shell or builds the Go executable automatically.

### Local startup rules

- Automatic startup applies only to the **default local** target. `GANTRY_HOME`
  selects the same sandbox state tree as the CLI.
- `--socket PATH` and `GANTRY_MANAGER_SOCKET` are **connect-only**, even when
  their path happens to equal the default. `--no-start` also disables startup.
- Only missing/refused sockets permit startup. Unsafe permissions, symlinks,
  incompatible protocols, authentication errors, and unhealthy existing
  managers are reported rather than replaced.
- Go serializes launchers, uses the existing manager-state ownership lock, and
  waits for a compatible health response. A TLS-only manager holding that
  state is not displaced. Saved policy-feed state requires an explicit
  `gantry serve` command with the correct governance configuration.
- The launched manager is same-user and Unix-only, detached from the terminal.
  Its diagnostics go to the private `manager.log` beside the socket. It remains
  running independently of the GUI; no sandbox is started by this operation.
- Automatic launch is attempted once per window. Polling continues to reconnect,
  but does not repeatedly spawn failing helpers. **Refresh** explicitly retries
  local startup.

Connect to a separately managed socket:

```sh
cargo run --locked --manifest-path desktop/Cargo.toml -- --socket /private/path/manager.sock
```

The socket must be private, owned by your account, and in a private directory.
It must serve the manager's HTTP API; a sandbox's `ctl.sock` is a different,
internal protocol and cannot be substituted.

## Remote managers — the same protocol over HTTPS

Use the existing Gantry remote-profile workflow:

```sh
gantry remote add team https://gantry.example.com:8443 --ca manager-ca.pem
gantry remote test team
cargo run --locked --manifest-path desktop/Cargo.toml -- --remote team
```

The CLI prompts for the manager token without echo; for automation, use its
`--token-file` or `--token-stdin` options. The desktop never accepts bearer values
on its command line. It reads the credential-free `remotes.json` and the
separate protected token file under the same Gantry configuration root.

TLS always checks the certificate chain, hostname, validity, and handshake
signatures. A profile's optional fingerprint **additionally** pins the leaf
certificate during the handshake, before sending authorization. Redirects,
plaintext remote URLs, credential-bearing URLs, and proxy-environment routing
are refused. Remote failures never launch or select a local manager.

Profiles and tokens are reloaded on refresh, under the CLI's shared profile-store
lock, so replacing a profile cannot pair its previous URL with a new token.
Revocation, token rotation, and CA changes do not require restarting the GUI.
The selected host remains visible in the header and footer, including offline.
`GANTRY_REMOTE` is not an implicit desktop selector; choose `--remote` explicitly.

## Demo and appearance

Preview without a manager, CLI, or virtualization access:

```sh
cargo run --locked --manifest-path desktop/Cargo.toml -- --demo --theme dark
```

Demo data is explicitly labeled and never used as a failure fallback.
`--theme system|dark|light` selects the initial appearance; the header control
cycles through all three. Theme and panel sizes are session-only. `--help` works
without a display.

## Included

- Gantry branding, semantic light/dark themes, and bundled icons.
- Virtualized sandbox table with resizable columns, status filters, and search.
- Resizable, scrollable inspector separating active allocation from saved
  next-boot settings, including restart-required notices.
- Loading, empty, no-match, and unavailable states; automatic reconnection.

| Shortcut | Action |
| --- | --- |
| Ctrl/⌘ F, or `/` in the table | Focus search |
| Enter while searching | Focus the inventory |
| ↑ / ↓ in the table | Select a sandbox and update its inspector |
| Escape in search | Clear the query |
| Ctrl/⌘ 1 | Focus the inventory |
| Ctrl/⌘ R | Refresh / retry the selected connection |
| Ctrl/⌘ Q | Quit the desktop only |

## Platform requirements

- **Linux:** a Wayland or X11 graphical session, working GPU/Vulkan driver,
  C/C++ toolchain, and GPUI's native development dependencies. See the upstream
  [bootstrap script](https://github.com/longbridge/gpui-kit/blob/main/script/bootstrap)
  for distribution-specific packages. Do not run as root.
- **macOS:** Rust and Xcode command-line tools. Unix sockets, detached startup,
  and protected remote profiles are implemented but have not been tested on macOS.
- **Windows:** this preview supports UI development with `--demo` only. Local
  connection/startup and protected remote-profile loading fail closed until
  Windows transport, ACL, and profile-lock support is implemented.

Rust 1.98.1 and Linux/Wayland have been used for validation. OS accessibility,
IME, HiDPI, and other platforms still need native review. There are no installers
or app bundles yet. The first Rust build downloads and compiles GPUI dependencies.

## Architecture and tests

`src/api.rs` is one typed client for `GET /v1/health` and `GET /v1/sandboxes` over
both transports, using the [manager contract](../api/managerapi/openapi.yaml).
`connector.rs` selects transport and owns startup policy; `launcher.rs` invokes
only `gantry serve --ensure`. Go owns daemon lifecycle, locks, policy, and the
existing sandbox sockets. Rust owns presentation, connection state, and TLS
client verification—not VM policy or lifecycle decisions.

All file, HTTP, and launcher work stays off the GPUI foreground thread. HTTP
requests, file/response sizes, launcher output, and readiness waits are bounded.
Inventory polls every three seconds with one refresh in flight; failures
clear stale rows. Selection by name, search, and filters survive successful
refreshes. SSE invalidation, lifecycle controls, image management, terminals,
and persistent preferences remain follow-up work.

```sh
cargo fmt --manifest-path desktop/Cargo.toml -- --check

# Protocol, TLS, profile security, launcher, and model tests; no GPUI build.
cargo test --locked --manifest-path desktop/Cargo.toml --no-default-features

# Also exercise real GPUI input, table, filter, theme, and layout behavior.
cargo test --locked --manifest-path desktop/Cargo.toml --features ui-tests
cargo clippy --locked --manifest-path desktop/Cargo.toml \
  --all-targets --all-features -- -D warnings

# Go launcher/manager ownership and concurrency tests.
go test -race ./internal/sandbox/manager
```

Tests use disposable sockets, TLS certificates, profiles, and manager state—not
your installed manager or sandboxes. TLS tests assert that an invalid chain,
hostname, expiry, or pin prevents any HTTP request from carrying the bearer.
GPUI tests use test windows, not a graphical session. `Cargo.lock` and the
`gpui-kit` facade are pinned; the Rust build remains separate from Gantry's Go build.
