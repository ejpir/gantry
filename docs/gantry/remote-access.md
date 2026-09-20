# Remote sandbox access

Gantry can manage another host through the [manager API](manager-api.md).
Remote transport is HTTPS with a manager bearer token. Organization login is
optional.

## Configure the manager

On the remote host, create a token and start a TLS listener:

```sh
umask 077
gantry serve --mint-token > /secure/path/manager.token
chmod 600 /secure/path/manager.token
gantry serve -listen tls://0.0.0.0:8443 \
  -tls-cert /secure/path/server.crt \
  -tls-key /secure/path/server.key \
  -token-file /secure/path/manager.token
```

The host needs Gantry's normal virtualization access. Protect the listener with
a trusted network, VPN, and firewall. A manager token grants host-shell
authority; it is not a scoped multi-tenant credential.

`--self-signed` can create a local CA under `~/.gantry/serve`. Copy its public
CA to clients through a trusted channel. TLS verification is always enabled;
plaintext listeners and insecure verification are unsupported.

The same manager can receive signed organization policy generations through
an outbound mTLS feed:

```sh
gantry serve -listen tls://0.0.0.0:8443 \
  -tls-cert /secure/path/server.crt -tls-key /secure/path/server.key \
  -token-file /secure/path/manager.token \
  -policy-feed /secure/path/organization-feed.json
```

The policy feed uses a separate client certificate and never receives the
manager bearer token. Its accepted generations govern all sandboxes managed by
this server. See
[Organization policy](organization-policy.md#receive-policy-updates).

## Add a client profile

```sh
gantry remote add home-lab https://gantry.example.com:8443 --ca manager-ca.pem
gantry remote test home-lab
```

Without a token flag, the CLI prompts without echo. For automation, prefer
`--token-file` or `--token-stdin`. Add `--fingerprint sha256:HEX` to pin the
exact leaf certificate in addition to normal CA and hostname checks.

Profiles are stored in `~/.gantry/remotes.json`; tokens are separate under
`~/.gantry/remotes/`. Token files use owner-only Unix permissions or a
protected Windows ACL and are rejected when other accounts can access them.

Remove a local profile with:

```sh
gantry remote rm home-lab
```

This does not delete remote sandboxes or revoke the server token.

### Connect through an SSH jump host

When the client can reach the manager only through an SSH host, use a local
forward. The repository includes a bootstrap script that securely copies the
CA, server certificate, and token through the jump host, pins the certificate,
and keeps an SSH control-master tunnel running:

```sh
JUMP=root@gateway.example \
MANAGER=gantry@192.168.1.160 \
GANTRY_BIN=./gantry \
./scripts/connect-remote-manager.sh
```

Set `MANAGER_HOST` separately when the SSH destination name is not the address
the jump host uses for the TLS listener. Stop the tunnel with:

```sh
JUMP=root@gateway.example ./scripts/connect-remote-manager.sh --stop
```

## CLI operations

Select a profile with `-remote NAME` or `GANTRY_REMOTE`. An explicit flag wins;
`-remote=""` forces local execution. Failed remote operations never fall back
to local.

```sh
gantry image pull alpine:latest -remote home-lab
gantry start dev -image alpine:latest -ssh -remote home-lab
gantry exec dev -remote home-lab -- uname -a
gantry configure dev -remote home-lab -mem 2048 -key settings-1
gantry stop dev -remote home-lab
gantry resume dev -remote home-lab
gantry delete dev -remote home-lab
```

Remote CLI creation is cache-only, so pull an image first. The TUI can pull a
missing image during its remote create flow.

Most path flags, including `-share`, `-kernel`, `-rootfs`, and `-net-policy`,
refer to paths on the manager host. Organization bundle/key flags and
`net-policy set` instead upload local policy data. Secret names resolve from
the manager's environment; desktop registry credentials are not copied.

Remote exec is bounded and non-interactive. Use SSH for terminals, SFTP, rsync,
and editors:

```sh
gantry ssh dev -remote home-lab
gantry ssh setup -remote home-lab
ssh dev.home-lab.gantry
```

The SSH host key is learned over authenticated TLS and pinned locally. A
changed key is refused until you verify it and explicitly accept it.

Remote image pulls and low-level `run` operations support idempotency keys and
bounded operation results. Organization-policy updates apply live by default;
pass `restart: true` or use `gantry policy set ... --restart` to explicitly
request controlled stop/update/resume. Events are current-state snapshots, not
durable history. See [Architecture](architecture.md#remote-manager-transport)
for routing, operation, and tunnel details.

## Create from the dashboard

Run `gantry tui`, press `n`, and choose:

- **Local** — create on this host.
- **Remote** — choose or add a standalone profile.
- **Organization** — sign in, choose a discovered manager, and provide its
  separate manager token if it is not registered.

TLS and authentication are tested before a profile is saved. Token fields are
masked, write-only, and cleared after submission or cancellation.

Open **Remotes (B)** to add, test, or remove profiles and to refresh
organization discovery. Profile and login changes appear without restarting
the dashboard. **Overview** and **Sandboxes** include authenticated remote
sandboxes alongside local ones; every remote row carries its profile tag so
same-named sandboxes remain distinct. The Traffic, Rules, Mounts, Ports,
Secrets, MCP, Packets, Audit, Images, and Registries views merge the manager's
source-tagged rows in the same way. Forms and destructive actions retain that
source identity and are executed by the owning manager, never by a same-named
local sandbox.

Enter on a running remote row opens a terminal through the authenticated SSH
upgrade. The dashboard enables that sandbox's SSH gateway live first when
needed; newly created remote sandboxes enable terminal access by default.
Remote host paths in share forms refer to the manager host, while a network
policy file is read on the client and uploaded as policy data. Secret and
registry values are write-only over the verified manager transport and never
appear in inventory responses. The **Remotes** view retains grouped connection
status and onboarding controls.

Full dashboard parity requires the same build on the client and manager. A new
client preserves lifecycle-only rows from an older manager, but telemetry and
configuration views become available only after upgrading and restarting
`gantry serve`.

A failed login, expired catalog, changed profile, missing token, or unreachable
manager never creates locally. Cancel and choose **Local** explicitly.

## Organization discovery

An organization login may return expiring manager suggestions. Discovery does
not install profiles, provide manager credentials, or grant manager access.
Registration still requires the manager's bearer token.

See [Organization login](organization-login.md) for the user flow and
[Architecture](architecture.md#dynamic-remote-catalog) for the catalog contract.
