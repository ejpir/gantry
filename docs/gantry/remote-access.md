# Remote sandbox access

Gantry can manage a remote host through the same [manager API](manager-api.md)
used locally. Remote transport is HTTPS with a manager bearer token. **A remote
can be standalone: organization membership and sign-in are not required.**

## Create from the TUI

Run `gantry tui` (or `gantry` in a terminal), then press **n**. The first step
chooses the location:

- **Local** — the existing local create form. No organization login or remote
  profile is needed. `GANTRY_REMOTE` does not redirect local dashboard actions.
- **Remote** — select a saved profile or **Add remote**. Enter a name, HTTPS URL,
  manager token, and optional CA file / certificate fingerprint. No IdP is
  contacted. TLS and authentication are tested **before** anything is saved.
- **Organization** — use a live organization receipt or sign in with your
  administrator's trusted configuration file. Choose a dynamically discovered
  remote. If it is not registered, supply that manager's separate token.

The create form names the selected remote and, when applicable, organization.
Remote images are pulled **on the manager host** when absent from its cache;
local kernel paths and registry credentials are not forwarded. Organization
creation revalidates the receipt/catalog and uploads the selected signed policy
for server-side verification before boot. A long image pull does not bypass
receipt expiry: sign-in is checked again before creation.

**No fallback:** a failed login, expired catalog, missing token, changed profile,
or unreachable manager cannot create a sandbox locally. Cancel and explicitly
choose Local if that is what you want.

### Manage profiles

Open **Remotes (B)**:

| Key | Action |
| --- | --- |
| **a** | Add a standalone remote; no org required |
| **t** | Test the selected configured remote |
| **d** | Confirm removal of its local profile and token |
| **enter** | Create on a configured remote, or register an org suggestion |
| **L** | Organization sign-in / refresh discovery |

Profiles and login/logout changes are picked up without restarting the TUI.
Remote inventory stays separate from local sandbox rows. Offline sources fail
independently. Removing a profile does **not** delete remote sandboxes or revoke
the manager token; rotate/revoke it on the manager host if needed. To replace a
profile or token through the TUI, remove the profile and add it again.

Token fields are masked, write-only, not copyable, and cleared on submission or
cancellation. Tokens are saved separately in private `0600` files; profile JSON
contains only connection metadata and public CA material.

## Configure a standalone manager

On the remote host, mint a token and start an HTTPS listener. For example:

```sh
umask 077
gantry serve --mint-token > /secure/path/manager.token
chmod 600 /secure/path/manager.token
gantry serve -listen tls://0.0.0.0:8443 \
  -tls-cert /secure/path/server.crt -tls-key /secure/path/server.key \
  -token-file /secure/path/manager.token
```

The manager host needs Gantry's usual virtualization access. Keep this listener
on a trusted network/VPN with appropriate firewall controls. The token has
**host-shell authority**, not per-organization/per-sandbox authorization. Do not
share a manager token as if it were a scoped multi-tenant credential.

Obtain the token and trust material through a secure administrative channel.
On the client, use the TUI or:

```sh
gantry remote add home-lab https://gantry.example.com:8443 --ca manager-ca.pem
# Without a token flag, an interactive CLI securely prompts for the token.

gantry remote test home-lab
gantry image pull alpine -remote home-lab
gantry start dev -image alpine -ssh -remote home-lab
gantry ssh dev -remote home-lab
```

Full certificate-chain and hostname verification is mandatory. `--fingerprint
sha256:HEX` adds an exact leaf-certificate pin; it does not replace CA trust.
For `serve --self-signed`, securely copy the generated public CA described in
[Manager API](manager-api.md). Plaintext TCP and certificate-verification
bypasses are not supported. Redirects are refused.

Profiles live in `~/.gantry/remotes.json`; tokens in
`~/.gantry/remotes/NAME.token`. With `GANTRY_HOME` set to the sandbox root, both
live beside that root. The CLI refuses group/world-readable token files.

## CLI operations

`-remote NAME` / `--remote NAME` can appear before the command or among its
flags. An explicit selector overrides `GANTRY_REMOTE`; `-remote=""` is an
explicit local request. Parsing stops at `--`, so guest arguments are untouched.
An explicitly remote unsupported command is refused, never executed locally.

```sh
gantry -remote home-lab ls
gantry exec dev -remote home-lab -- uname -a
gantry configure dev -remote home-lab -ssh=true -mem 1024 -key dev-settings-1
gantry stop dev -remote home-lab
gantry resume dev -remote home-lab
gantry delete dev -remote home-lab

gantry image ls -remote home-lab
gantry image pull -key MY_RETRY_KEY debian:bookworm-slim -remote home-lab
gantry image wait OPERATION_ID -remote home-lab
gantry image rm alpine -remote home-lab

gantry events -remote home-lab
gantry net-policy set dev policy.json -remote home-lab
gantry net-policy show dev -remote home-lab
gantry policy show dev -remote home-lab
gantry audit dev -remote home-lab
```

CLI `start` is cache-only; pull first. Flag paths such as `-share`, `-kernel`,
`-rootfs`, and `-net-policy` on `start` resolve **on the manager host**. The
organization `-org-policy` / `-org-policy-key` files are the exception: they are
read locally and uploaded as a verified signed snapshot. `net-policy set`
also uploads its local document, rather than forwarding a client path.

### Configure and low-level run

`configure` preserves omitted settings, including explicit `-ssh=false` and
`-devcontainers=false`. SSH can change live; resource and Dev Containers
topology changes on a running sandbox report **restart required**. Stopped
updates use the same launch lock and configuration transaction as local updates.
`-key KEY` makes an ambiguous retry replay the same operation/result.

`run` retains the local command's low-level meaning: boot explicit kernel/disk
assets, **not** an OCI image or a named persistent sandbox. Paths refer to the
manager's filesystem/cwd; the client does not open them. For example:

```sh
gantry run -remote home-lab -kernel /srv/gantry/kernel \
  -rootfs /srv/gantry/system.erofs -timeout 60 -max-output 16384 -key raw-vm-1
```

Remote raw runs are noninteractive, with captured console output (default
16 KiB, maximum 64 KiB), optional piped serial input up to 64 KiB, and a deadline
(default 300 seconds, maximum 3600). The existing local launcher runs in a
short-lived helper, retaining its pinned-file/share restrictions. Deadline,
submission-connection loss or manager shutdown terminates and reaps that helper.
A completed run includes its process exit code: **124** for deadline, **130**
for cancellation. Output truncation is reported; guest output cannot grow the
manager without bound. Use a unique `-key` and reuse it only for retries of the
same run; replay never boots a second VM while the operation record is retained.
Raw runs are serialized separately from named sandbox operations.

Remote `exec` is bounded and noninteractive (stdin up to 1 MiB, timeout up to
3600 seconds). Use SSH for terminals, SFTP, rsync and remote editors:

```sh
gantry ssh setup -remote home-lab
ssh dev.home-lab.gantry
```

SSH tunnels reuse the existing sandbox gateway and its channel restrictions.
The host key is initially learned over authenticated TLS. A changed key is
refused until verified with the operator and explicitly accepted:

```sh
gantry ssh-known-hosts -remote home-lab --accept-new-key
```

Image pulls survive client disconnection, publish bounded progress and can be
reattached by operation ID. Operation records are in manager memory, not durable
restart recovery. Registry login/helpers run on the manager host; credentials
are never copied from your desktop. SSE reconnects resnapshot current state;
it does not promise historical event replay.

## Organization discovery is optional

See [Organization login](organization-login.md) to sign in, or
[Architecture](architecture.md#dynamic-remote-catalog) for trusted catalog
configuration and the service contract. An IdP authenticates the
user; it does not inherently provide a Gantry remote inventory. Catalog lookup
is dynamic at sign-in and caches only public, expiring metadata. Sign in again
to refresh it; no login/access/refresh tokens are retained for background use.
Discovery does not grant manager access and never installs a profile or token
without your action. Standalone profiles continue to work independently of
organization login/logout.

## Validation

`./scripts/test-manager-api-e2e.sh` runs M2 safety unit tests, then the real-manager
TLS/CLI lifecycle battery, live/stopped `configure`, low-level VM deadline
checks, and real SSH/SFTP through the TLS tunnel. SSH coverage includes command
output/exit status, binary file round-trip, forwarding refusal, live disable,
and host-key rotation refusal/explicit acceptance. It requires virtualization,
guest assets, and OpenSSH `ssh`/`sftp`; user SSH configuration is untouched. Pass **`-api-only`** for
real-manager auth, dispatch, stopped configuration, idempotency, helper failure,
and no-local-fallback checks without downloading assets or booting a VM. This
subset is not a substitute for the full hardware battery.

[Remote TUI E2E](../../tests/e2e/remotetui/README.md) drives a real Gantry binary
through a POSIX PTY against disposable HTTPS fixtures. It covers standalone
registration, token refusal/storage, create routing, test/removal, and browser
OIDC/catalog onboarding. It needs neither external accounts nor virtualization.
It does **not** boot VMs or certify production IdPs/catalogs; actual VM/SSH and
policy-egress validation requires a suitable manager host.
