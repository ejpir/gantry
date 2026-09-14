# Standalone organization OIDC E2E

```sh
go build -o /tmp/gantry ./cmd/gantry
go run ./tests/e2e/oidc -gantry /tmp/gantry
```

On Windows, choose a writable executable path ending in `.exe`. To distribute a
standalone driver, build `./tests/e2e/oidc` for the host alongside Gantry and invoke
it with `-gantry PATH`. `-timeout` bounds the complete battery (default two minutes).
CI runs the driver in its Linux, Windows and macOS test matrix.

No hypervisor, VM image, public egress, external account, OPA/OpenSSL executable,
Docker, or deployed identity service is required. This is **OIDC/CLI E2E**, not
VM enforcement validation; use `tests/e2e/policy` for the latter.

## Our test IdP

`internal/orgauth/testidp` starts a disposable HTTPS server on IPv4 loopback.
Each run gets fresh TLS and RSA JWT signing keys; the policy bundle uses a
separate signing key. Only the temporary test configuration trusts its CA.

The fixture implements discovery, authorization-code issuance, single-use code
redemption, S256 PKCE checking, client/redirect binding, RS256 ID tokens, and JWKS.
It automatically authenticates one synthetic user. An HTTP client emulates browser
navigation, but the **real Gantry subprocess** performs discovery, callback
validation, code exchange, `coreos/go-oidc` verification, membership selection,
receipt persistence, and policy application. There is no production test bypass
or injected verifier. This fixture is not a production IdP or a vendor UI/MFA test.

## Coverage

- Correct issuer/client/subject/profile/revision and membership mapping.
- Wrong signature, issuer, audience, nonce, authorized party, missing subject,
  future issue/not-before time, expired/missing ID token, and access-token hash.
- Multiple audiences without `azp`, absent/unmapped groups, unauthorized explicit
  profile selection, and ambiguous versus explicitly selected profiles.
- Wrong/duplicate callback state, wrong callback issuer, provider denial, and
  rejected PKCE redemption.
- Wrong discovery issuer, insecure advertised endpoint, oversized metadata,
  and blocked token-endpoint redirects. Endpoint counters confirm real exchanges.
- Failed first login creates no receipt; subsequent failures preserve the previous
  successful receipt. Another CLI process can read the receipt.
- Explicit application to a **stopped configuration fixture**, pinned restart
  semantics after source corruption, local logout, and actual ID-token expiry.
  Unit tests separately cover live-sandbox refusal using its lifetime lock,
  callback replay/host/method/path checks, receipt permissions/symlinks, and custody
  rejection. No daemon or VM is started by this driver.
- Raw ID/access/refresh tokens, authorization codes, PKCE verifiers, private keys
  and provider error canaries must not appear in CLI output or persisted files.

All fixture/state files live in an owned temporary workspace, removed on success
or failure. Command output is bounded, checked for leaks, and not dumped on a
failure. Child processes have deadlines; errors cannot masquerade as expected
denials merely by crashing or failing to launch.
