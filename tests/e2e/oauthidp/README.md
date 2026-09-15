# Disposable OAuth authorization server

This helper runs the protocol-level loopback fixture from
`internal/orgauth/testidp` for `scripts/oauth-custody-e2e.py`. It implements a
public authorization-code client with S256 PKCE, single-use codes, RFC 8707
resource binding, refresh-token rotation, a device grant, authorization-server
metadata, and a protected MCP endpoint.

It is test infrastructure, not a production IdP or a vendor login/MFA emulator.
The process prints one JSON readiness record; issued credentials never appear in
its output. The Linux KVM and macOS HVF orchestrators build and stage the helper
automatically.

For a standalone real-VM run, follow
[`scripts/aws-kvm/README.md`](../../../scripts/aws-kvm/README.md).
