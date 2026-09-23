# Organization policy

Organization policy adds rules for network access, shared directories, MCP
tools and brokered credentials. It is optional and never relaxes Gantry's
existing safety checks.

## Start with your organization's policy

Ask your administrator for a signed bundle, its trusted public key and a
profile name:

```sh
gantry start dev -image alpine:latest \
  -org-policy bundle.tar.gz -org-policy-key public.pem \
  -policy-profile developer
```

You can also select a policy through [Organization login](organization-login.md).
Do not enable `-oauth-custody` on a governed sandbox.

## Inspect and troubleshoot

```sh
gantry policy show dev       # saved organization policy
gantry net-policy show dev   # effective network rules
gantry audit dev            # recent authorization decisions
```

In `gantry tui`, press **A** for Audit, then **Enter** to inspect an event.
A denied operation needs an appropriate policy grant; local settings cannot
override an organization denial.

## Update or remove a policy

Changes apply live to a running sandbox and are saved for its next start:

```sh
gantry policy set dev -bundle updated.tar.gz -key public.pem -profile developer
```

Use `--restart` to explicitly request stop/update/resume instead:

```sh
gantry policy set dev -bundle updated.tar.gz -key public.pem \
  -profile developer --restart
```

`gantry policy clear dev` also applies live. Add `--restart` if you want a
controlled restart. Editing the original bundle file does not update a sandbox
automatically.

Policies expire. An expired policy denies further access and triggers sandbox
shutdown; obtain an updated bundle before resuming.

## Receive policy updates

A long-running manager can poll one organization-wide policy feed over
mutually authenticated HTTPS. The local configuration pins the organization,
profile, signing key, and client identity:

```json
{
  "version": 1,
  "organization": "example-company",
  "profile": "developer",
  "url": "https://policy.example.com/v1/gantry",
  "public_key": "org-public.pem",
  "ca_file": "policy-service-ca.pem",
  "client_certificate": "gantry-host.pem",
  "client_key": "gantry-host-key.pem",
  "poll_interval_seconds": 30
}
```

Paths are relative to the feed configuration. The client key must have
owner-only permissions or a protected Windows ACL. Start the receiver with:

```sh
gantry serve -policy-feed organization-feed.json
```

Only one feed may be configured for a manager. The endpoint returns the
current organization generation and signed bundle; `bundle` is base64-encoded:

```json
{
  "version": 1,
  "organization": "example-company",
  "generation": 42,
  "bundle": "H4sI..."
}
```

Generation numbers must increase and cannot change content after use. Gantry
uses conditional requests and sends `Prefer: wait=30`, so a service can hold an
unchanged answer and reply the moment a new generation exists. Each request
reports the host's position in headers:

| Header | Meaning |
|---|---|
| `X-Gantry-Policy-Generation`, `X-Gantry-Policy-Digest` | Last generation applied to every sandbox, and its digest |
| `X-Gantry-Policy-Pending-Generation` | A received generation not yet applied everywhere |
| `X-Gantry-Policy-Pending-Attempts`, `X-Gantry-Policy-Pending-Failed` | Fan-out attempts so far, and how many sandboxes refused the last one (`unknown` if none were reached) |
| `X-Gantry-Policy-Rejected-Generation`, `X-Gantry-Policy-Rejected-Reason` | The last response the host refused: `verification`, `organization`, `rollback`, `changed`, or `invalid` |
| `X-Gantry-Policy-Profile`, `User-Agent` | The locally pinned profile and the Gantry version |

Only counts and fixed words are reported. Sandbox names and failure causes
stay in the host's audit log. A newly applied generation is reported
immediately rather than on the next poll.

Protected manager state stages a received generation before fan-out and caches
the signed current or pending bundle. After a crash, the manager
restores mandatory admission and attempts the pending fan-out before serving
lifecycle requests; failed targets remain stopped and the newer cursor remains
unreported until retry succeeds. It never copies the mTLS client key into
cursor state.

When a new generation arrives, the manager fans it out to every saved sandbox.
Running sandboxes update without replacing their VM or daemon; stopped
sandboxes save it for their next start. Sandboxes created later through that
manager inherit the current snapshot. While the feed is active, manager API
clients cannot replace or clear its policy, and low-level unmanaged VM runs are
refused.

Each sandbox moves network, shares, MCP, brokered credentials, persistence, and
expiry as one fail-closed transaction. Existing shares denied by the new policy
become inaccessible; a later generation can restore them. Active MCP sessions
close and may reconnect under the new policy. A target that cannot reconcile is
stopped, cannot be resumed through that manager until it accepts the current
snapshot, and does not prevent processing other targets. The aggregate
generation is not acknowledged until all targets succeed; the receiver retries
it on every poll and keeps polling meanwhile, so the service sees the failure
and a newer generation can replace the stuck one.

Manual per-sandbox policy remains available when no organization-wide feed is
active. The manager API and remote CLI accept `restart: true` / `--restart` to
explicitly select controlled stop/update/resume for those manual changes.

## Run a policy service

`gantry policy-service` is a complete feed for one organization. Host managers
poll it over mutual TLS. Administrators publish signed generations through its
API and roll them out ring by ring. It never holds the signing key: it only
verifies bundles with the same public key every host pins.

```sh
gantry policy keygen -out ~/secure/acme-key      # signing-key.pem stays with administrators
gantry policy-service init -dir /srv/acme-policy -organization acme \
  -url https://policy.acme.dev:8443 -public-key ~/secure/acme-key/public.pem
gantry policy-service admin add -dir /srv/acme-policy -name ops-admin   # prints a token once
gantry policy-service serve -dir /srv/acme-policy
```

`init` creates a private directory holding the host CA, a TLS certificate for
the URL's host (add more names with `-name`), and the rings `canary`, `early`,
and `everyone` (choose your own with repeated `-ring`). The CA is in `ca.pem`.
Register the service like a remote manager, and the Gantry desktop opens it as
an organization workspace:

```sh
gantry remote add acme https://policy.acme.dev:8443 --ca ca.pem --token-stdin
```

**Enroll a host.** On the host, create a key and a certificate request. The key
never leaves that directory:

```sh
gantry policy feed-request -out ~/.gantry/acme-feed -host dev-mac-031
```

An administrator enrolls `host.csr` with a profile and ring. The service
returns `feed.json`, `host.pem`, `ca.pem`, and `org-public.pem`. Place them in
the same directory and start the manager with
`gantry serve -policy-feed ~/.gantry/acme-feed/feed.json`.

**Publish.** Sign a `data.json` on the administrator's machine with
`gantry policy sign -signing-key`, then post the bundle to
`POST /v1/admin/generations`. The Gantry desktop does all of this from its
Policy screen. Before accepting it, the service checks:
- the signature verifies with the pinned key;
- the organization matches;
- every enrolled host's profile exists in the bundle.

It then assigns the next generation number and serves it to the first ring.
`POST /v1/admin/rollout/promote` extends it to later rings. A host moved to an
earlier ring is never served an older generation.

**Roll back.** `POST /v1/admin/generations/{n}/republish` serves generation
*n*'s signed bundle, unchanged, under the next number. Its expiry is kept.

**Watch.** `GET /v1/admin/hosts` shows each host's target generation and
latest report. Its status is one of `current`, `offered`, `pending`, `stalled`,
`rejected`, `mismatch`, `silent`, or `never`. A `mismatch` means the host
applied the right generation, but with a different profile or key than it was
enrolled with.

Revoking a host (`POST /v1/admin/hosts/{name}/revoke`) makes the feed refuse
its certificate. The service is the only party that trusts these certificates,
so no revocation list is needed. The wire types are in `api/policyservice`.

## Try a local test policy

No OPA or OpenSSL installation is needed:

```sh
gantry policy generate -out local-policy -mount "$PWD" -ttl 30d
gantry policy verify -bundle local-policy/bundle.tar.gz \
  -key local-policy/public.pem -profile developer
```

Use a new output directory. The policy allows read-only access to the directory
passed with `-mount` and denies other governed access, including network, MCP
and credentials. Its temporary signing key is not saved and is **for testing only**.
Use the generated bundle and public key with the launch flags above; add
`-net=false -share "code=$PWD,ro"` for a simple offline example.

To customize it, edit `local-policy/source/data.json`, then re-sign into a new
directory:

```sh
gantry policy sign -data local-policy/source/data.json \
  -out local-policy-v2 -ephemeral
```

Re-signing does not extend expiry or change an existing sandbox. Keep real
signing keys outside the repository and guest shares. “Manager-wide” covers
sandboxes controlled through that `gantry serve` process and its shared state;
the trusted host owner can still stop the manager or invoke local tooling. This
is not OS-enforced mandatory organization enrollment.

For policy fields, stable signing keys, network semantics and security limits,
see [Architecture](architecture.md#organization-policy-engine).
