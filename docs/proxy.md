# Forward-proxy routing

Gantry can point proxy-aware software in a sandbox at an existing forward
proxy. It does not embed a second proxy or terminate TLS.

```sh
gantry start agent -image alpine:latest \
  -proxy http://proxy.example:3128 \
  -no-proxy localhost,127.0.0.1,.corp.example \
  -proxy-enforce
```

`-proxy` accepts `http`, `https`, `socks5`, and `socks5h` URLs. SOCKS URLs must
include a port. Proxy credentials are rejected because the URL is persisted in
`sandbox.json`; use Gantry's in-memory secrets for sensitive environment
variables instead.

Every session receives `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY`, their
lowercase equivalents, and both spellings of `NO_PROXY`. Without an explicit
`-no-proxy`, localhost and IPv4/IPv6 loopback are bypassed. Gantry replaces
same-named variables from the OCI image rather than emitting duplicate entries.

## Enforcement

Environment variables are advisory: an application can ignore or replace
them. `-proxy-enforce` adds a host-side backstop:

- allow TCP only to each IPv4 address of the proxy on its configured port;
- deny direct TCP ports 80 and 443; and
- deny direct UDP port 443, including ordinary QUIC/HTTP3 traffic.

Other ports remain governed by the sandbox's normal network policy. This is
not protocol-aware transparent interception, so HTTP or TLS deliberately sent
over an unusual port is not identified as web traffic. Use an explicit
default-deny network policy when every non-proxy destination must be blocked.

The proxy hostname is resolved when the sandbox network starts. Restart the
sandbox to refresh changed proxy addresses. When DNS filtering is configured,
Gantry permits resolving the proxy hostname without adding its answers to the
policy's broad dynamic allow table. Enforcement requires the embedded netstack
and cannot be combined with `-gvproxy`.
