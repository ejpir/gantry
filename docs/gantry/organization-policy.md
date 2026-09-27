# Organization policy

Organization policy can restrict a sandbox's network, host shares, MCP tools,
and brokered credentials. It is optional. Local settings cannot override an
organization denial.

## Apply and inspect a policy

Ask your administrator for a signed bundle, its trusted public key, and your
profile name:

```sh
gantry start dev -image alpine:latest \
  -org-policy bundle.tar.gz -org-policy-key public.pem \
  -policy-profile developer
```

You can also choose a policy through [Organization login](organization-login.md).
Governed sandboxes cannot use `-oauth-custody`.

```sh
gantry policy show dev       # saved policy
gantry net-policy show dev   # effective network rules
gantry audit dev            # recent decisions
```

In `gantry tui`, press **A** to view audit events. Ask your administrator to
review a denied operation; changing local settings cannot grant it.

## Update or remove a policy

A running sandbox updates live; a stopped sandbox uses the change on its next
start:

```sh
gantry policy set dev -bundle updated.tar.gz -key public.pem -profile developer
gantry policy clear dev
```

Add `--restart` to either command if you want a controlled stop/update/resume.
Editing the original bundle file does not update a sandbox. An expired policy
denies access and stops the sandbox; obtain a renewed bundle before resuming.

## Receive policy updates

An organization can send signed generations to a long-running manager. For
a manually enrolled host, place its `feed.json` and certificates beside its
private key, then start (or restart) the manager with its existing listener and
authentication flags plus:

```sh
gantry serve -policy-feed /secure/host/feed.json
```

The host keeps its private key; the feed uses mutual TLS rather than your
[organization login](organization-login.md). One feed governs **all** saved
sandboxes on that manager, including future ones. Running sandboxes update
live; stopped ones stay stopped. A sandbox that cannot accept a generation is
stopped while the manager retries and keeps reporting the failure. While the
feed is active, individual policies cannot be replaced through the manager.

The service's enrollment flow below creates `feed.json`. For manually hosted
feeds, the [configuration and protocol](architecture.md#policy-distribution-and-live-rollout)
are in Architecture.

## Run a policy service

`gantry policy-service` distributes signed policy to one organization. It uses
a separate signing key, administrator token, and host certificates. Run it at
a URL enrolled hosts can reach:

```sh
gantry policy keygen -out ~/secure/acme-key
gantry policy-service init -dir /srv/acme-policy -organization acme \
  -url https://policy.acme.dev:8443 -public-key ~/secure/acme-key/public.pem
gantry policy-service admin add -dir /srv/acme-policy -name ops-admin
gantry policy-service serve -dir /srv/acme-policy
```

`admin add` prints the token once. Keep the signing key on an administrator's
machine, **not** on the service or in a guest share. The service's `ca.pem`
verifies its TLS certificate; copy it to each administrator who connects.
Rings default to `canary`, `early`, and `everyone` (override at `init` with
repeated `-ring`).

Register the service as an administration workspace in Gantry desktop:

```sh
gantry remote add acme https://policy.acme.dev:8443 --ca ca.pem --token-stdin
```

Supply an administrator token on stdin. This token administers the service,
not a sandbox manager. The desktop offers **Hosts, Policy, Rollouts, History,
and Enrollment** for this workspace.

### Enroll a host manager

For a manager you already registered as a remote, open the policy service's
desktop **Enrollment** page and choose **Enroll managed remote…**. Select the
manager, policy profile, and ring, then confirm. Desktop transfers only the
CSR and public enrollment files between the two separately authenticated
connections; the private key is created on the manager host and never leaves
it. The result is **staged, not enforcing**. Publish a signed generation for
its ring, then choose **Activate feed…** and select the remote. The manager
verifies the pinned identity, fetches the signed generation, and applies it to
every saved sandbox before reporting success; it does not restart. If the
service is unreachable or has nothing published, activation is refused and
enrollment remains staged. Failed sandbox targets are subject to a
fail-closed stop and retried under mandatory policy; inspect any stop failure.
Do not mistake `activating` or `configured` without an applied generation for
enforcement.

Successful activation is durable: later starts with the manager's existing
flags reload **only** that activated, pinned feed. A staged but inactive
manager still refuses restart without `-policy-feed`; an explicit restart with
the displayed path remains the fallback. The enrolled host appears as `never`
in the service until it polls. The feed URL must be reachable **from the
manager host**, not just through an SSH forward on the desktop.

To enroll a host that is *not* a registered remote, on the **host** create its
private key and certificate request manually:

```sh
gantry policy feed-request -out ~/.gantry/acme-feed -host dev-mac-031
```

Send only `host.csr` to an administrator. In desktop **Enrollment**, enroll it
with a profile and ring; return `feed.json`, `host.pem`, `ca.pem`, and
`org-public.pem` to the host. Place them beside `host-key.pem`, then restart
its existing manager with `-policy-feed ~/.gantry/acme-feed/feed.json`.
Never send the host's private key. This manual flow is still available from
**Enroll host…** in desktop.

### Publish and monitor

In desktop **Policy**, edit the draft and review its changes, then choose a
local signing key and **Sign & Publish**. The service verifies the signature,
organization, and enrolled profiles before making the new generation available
to the first ring. Use **Rollouts** to promote it to later rings and **Hosts**
to spot stalled or mismatched hosts. **Enrollment** can revoke a host.

For an API client, sign locally with `gantry policy sign -signing-key`, then
publish through the [administrator API](architecture.md#organization-policy-service).
**History → Republish** rolls back to an earlier signed bundle under a new
generation number; it does **not** extend that bundle's expiry.

Enrollment is opt-in by each host owner; the service is not mandatory
host-wide enforcement. See [Architecture](architecture.md#organization-policy-service)
for transport, reporting, persistence, and security limits.

## Try a local test policy

No OPA or OpenSSL installation is needed:

```sh
gantry policy generate -out local-policy -mount "$PWD" -ttl 30d
gantry policy verify -bundle local-policy/bundle.tar.gz \
  -key local-policy/public.pem -profile developer
```

Use a new output directory. This test policy allows read-only access to the
chosen directory and denies other governed access, including network, MCP,
and credentials. Its temporary signing key is **not saved**; use a stable
signing key for real policies. To customize the example, edit
`local-policy/source/data.json` and sign it into a *new* directory.

For policy fields and enforcement details, see
[Architecture](architecture.md#organization-policy-engine).
