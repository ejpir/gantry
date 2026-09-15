# Ready-to-use local OPA test bundle

Files:

- `bundle.tar.gz`: RS256-signed, data-only OPA bundle.
- `public.pem`: matching RSA-3072 verification key, **for testing only**.
- `source/data.json`: editable policy source; editing it does not change the bundle.

Profile: **developer**. Organization: `local-test`.
Revision: `test-20260913T222303Z`. Expires: **2026-10-13 22:23:03 UTC**.
The private signing key was never saved.

This snapshot grants read-only mounts under
`/Users/eh04xk/repos/minivm`, filesystem MCP connection/listing and the
`read_file` / `list_directory` calls, and brokered credentials for `github.com`.
It permits IPv4 TCP port 443 except `169.254.0.0/16`, and DNS for `github.com`,
`*.githubusercontent.com`, and `*.docker.io`. All other organization-layer
requests deny. The local policy and existing host safety checks still apply;
DNS permissions are not strict hostname-based connection isolation.

## Try it

Run from the repository root with a rebuilt Gantry:

```sh
gantry policy verify -bundle examples/org-policy-test/bundle.tar.gz \
  -key examples/org-policy-test/public.pem -profile developer

gantry policy check -bundle examples/org-policy-test/bundle.tar.gz \
  -key examples/org-policy-test/public.pem -profile developer \
  -action mcp.tools.call -resource '{"server":"fs","tool":"read_file"}'

# Expected denial, exit 1:
gantry policy check -bundle examples/org-policy-test/bundle.tar.gz \
  -key examples/org-policy-test/public.pem -profile developer \
  -action mcp.tools.call -resource '{"server":"fs","tool":"write_file"}'
```

To test actual authorization events (requires working VM assets):

```sh
gantry start policy-demo -oauth-custody=false -mcp \
  -org-policy examples/org-policy-test/bundle.tar.gz \
  -org-policy-key examples/org-policy-test/public.pem -policy-profile developer \
  -share "code=$(pwd -P),ro"

# Expected denial; the existing read-only export is preserved.
gantry share add --replace policy-demo "code=$(pwd -P)"
gantry audit policy-demo
gantry tui  # press A for Audit
```

Use a new sandbox name. The share command assumes your canonical checkout path
matches the signed path above; otherwise regenerate or edit/re-sign first.
Offline `policy check` does not add events to a sandbox audit trail. Governance
does not support OAuth custody. Host-side image/asset downloads are not governed.

## Generate or re-sign with Gantry

No OPA CLI or OpenSSL executable is needed:

```sh
# Fresh, stricter defaults: only this read-only mount; network/MCP/credentials deny.
gantry policy generate -out examples/my-policy -mount "$PWD" -ttl 30d

# Preserve this example's grants after editing its path, revision and expiry:
gantry policy sign -data examples/org-policy-test/source/data.json \
  -out examples/updated-policy -ephemeral

# Or use an existing trusted signer instead of a fresh test key:
gantry policy sign -data examples/org-policy-test/source/data.json \
  -out examples/org-signed-policy -signing-key /secure/outside-shares/org-private.pem
```

Every output directory must be new. Ephemeral signing rotates the public key;
no existing sandbox is changed. To adopt the result, use its bundle and public
key at launch, or `gantry policy set NAME ...` while the sandbox is stopped.
Signing does not extend expiry or bump the revision automatically. Never keep
real signing keys in this repository or in guest shares.

See [Organization policy](../../docs/gantry/organization-policy.md) for everyday
usage and [Architecture](../../docs/gantry/architecture.md#organization-policy-engine)
for the schema and security limitations.
