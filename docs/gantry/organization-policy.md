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

Changes require a stopped sandbox:

```sh
gantry stop dev
gantry policy set dev -bundle updated.tar.gz -key public.pem -profile developer
gantry resume dev
```

To remove the organization policy, run `gantry policy clear dev` while stopped.
Editing the original bundle file does not update a sandbox automatically.

Policies expire. An expired policy denies further access and triggers sandbox
shutdown; obtain an updated bundle before resuming.

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
signing keys outside the repository and guest shares. The host owner remains
in control; this is not mandatory organization enrollment.

For policy fields, stable signing keys, network semantics and security limits,
see [Architecture](architecture.md#organization-policy-engine).
